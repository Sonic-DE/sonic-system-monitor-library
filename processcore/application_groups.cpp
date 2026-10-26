/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include "application_resolver_p.h"
#include "cgroup.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <utility>

using namespace KSysGuard;
using namespace KSysGuard::ApplicationTracking;

namespace {
bool isBackgroundGroup(const QString &path)
{
    // Preserve the mappings shipped by the previous Applications view. These
    // are optional metadata rules, not required service-manager functionality.
    static const QStringList mappings = {QStringLiteral("session.slice"),
                                         QStringLiteral("background.slice"),
                                         QStringLiteral("org.a11y.atspi.Registry"),
                                         QStringLiteral("org.kde.discover.notifier"),
                                         QStringLiteral("geoclue"),
                                         QStringLiteral("org.kde.kunifiedpush"),
                                         QStringLiteral("dconf.service"),
                                         QStringLiteral("flatpak-session-helper.service"),
                                         QStringLiteral("gpg-agent.service"),
                                         QStringLiteral("org.kde.xwaylandvideobridge"),
                                         QStringLiteral("org.kde.kalendarac"),
                                         QStringLiteral("xdg-desktop-portal-gtk.service"),
                                         QStringLiteral("org.kde.kdeconnect"),
                                         QStringLiteral("org.kde.kwalletd6"),
                                         QStringLiteral("org.kde.kclockd")};
    for (const auto &mapping : mappings) {
        if (path.contains(mapping, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

Application describeGroup(const QString &path)
{
    if (isBackgroundGroup(path)) {
        return {QStringLiteral("services"), {}, QStringLiteral("preferences-system-services"), QStringLiteral("services"), true};
    }
    // A real, discovered kernel group is used for metadata only. In particular,
    // no provider cgroupData override is called to aggregate the new model.
    CGroup group(path);
    const auto service = group.service();
    const auto id = service->storageId().isEmpty() ? service->name() : service->storageId();
    return {id, service->name(), service->icon(), service->menuId(), false};
}

bool isApplicationGroup(const QString &path)
{
    return (path.endsWith(QLatin1String(".scope")) || path.endsWith(QLatin1String(".service")))
        && (isBackgroundGroup(path) || path.contains(QLatin1String("/app-"))
            || (path.contains(QLatin1String("/flatpak")) && path.endsWith(QLatin1String("scope"))));
}

void mergeKernelGroups(GroupCatalog &catalog, const QString &desktopPath, const QList<ProcessInfo> &processes)
{
    QHash<QString, QString> applicationByPath;
    for (const auto &app : std::as_const(catalog.applications)) {
        for (const auto &origin : app.origins) {
            applicationByPath.insert(origin, app.id);
        }
    }
    for (const auto &process : processes) {
        const auto path = process.cgroup;
        if (process.pid <= 1 || !path.startsWith(desktopPath + QLatin1Char('/')) || !isApplicationGroup(path)) {
            continue;
        }
        auto id = applicationByPath.value(path);
        if (id.isEmpty()) {
            const auto app = describeGroup(path);
            if (app.id.isEmpty()) {
                continue;
            }
            id = app.id;
            auto &merged = catalog.applications[id];
            if (merged.id.isEmpty()) {
                merged = app;
            }
            merged.origins.append(path);
            applicationByPath.insert(path, id);
        }
        if (!catalog.bindings.contains(process.pid)) {
            catalog.bindings.insert(process.pid, {id, process.startTime});
        }
    }
    for (auto &app : catalog.applications) {
        app.origins.sort();
    }
}
}

GroupCatalog KSysGuard::ApplicationTracking::discoverGroups(const QString &cgroupRoot, qint64 uid, const QList<ProcessInfo> &processes)
{
    GroupCatalog result;
    const auto desktopPath = QStringLiteral("/user.slice/user-%1.slice/user@%1.service").arg(uid);
    const auto base = QDir::cleanPath(cgroupRoot);
    const auto root = base + desktopPath;
    if (cgroupRoot.isEmpty() || !QFileInfo(root).isDir()) {
        // Kernel membership strings may remain readable through procfs when the
        // optional group mount is absent or hidden. Preserve visible unknown
        // apps/services from that evidence too; absence of a catalog never
        // establishes an authoritative filter for the rest of the inventory.
        mergeKernelGroups(result, desktopPath, processes);
        return result;
    }
    result.available = true;
    result.complete = QFileInfo(root).isReadable();
    if (!result.complete) {
        result.issues.append(QStringLiteral("group-directory-unreadable"));
    }
    QMap<qint64, ProcessInfo> inventory;
    for (const auto &process : processes) {
        if (process.pid > 1) {
            inventory.insert(process.pid, process);
        }
    }
    QMap<QString, QString> applicationByPath;
    QMap<qint64, QStringList> candidates;
    QDirIterator iterator(root, QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks, QDirIterator::Subdirectories);
    int directories = 0;
    while (iterator.hasNext()) {
        const auto directory = iterator.next();
        if (!QFileInfo(directory).isReadable()) {
            result.complete = false;
            result.issues.append(QStringLiteral("group-directory-unreadable"));
        }
        if (++directories > 65536) {
            result.complete = false;
            result.issues.append(QStringLiteral("group-directory-limit"));
            break;
        }
        const auto path = directory.mid(base.size());
        if (!isApplicationGroup(path)) {
            continue;
        }
        auto app = describeGroup(path);
        if (app.id.isEmpty()) {
            result.complete = false;
            result.issues.append(QStringLiteral("group-identity-unavailable"));
            continue;
        }
        auto &merged = result.applications[app.id];
        if (merged.id.isEmpty()) {
            merged = app;
        }
        merged.origins.append(path);
        applicationByPath.insert(path, app.id);
        QFile pids(directory + QStringLiteral("/cgroup.procs"));
        if (!pids.open(QIODevice::ReadOnly)) {
            result.complete = false;
            result.issues.append(QStringLiteral("group-membership-unreadable"));
            continue;
        }
        constexpr qint64 maximumMembershipBytes = 16 * 1024 * 1024;
        const auto bytes = pids.read(maximumMembershipBytes + 1);
        if (bytes.size() > maximumMembershipBytes) {
            result.complete = false;
            result.issues.append(QStringLiteral("group-membership-limit"));
            continue;
        }
        for (const auto &line : bytes.split('\n')) {
            if (line.trimmed().isEmpty()) {
                continue;
            }
            bool valid = false;
            const auto pid = line.trimmed().toLongLong(&valid);
            if (!valid || pid <= 0) {
                result.complete = false;
                result.issues.append(QStringLiteral("group-membership-malformed"));
                continue;
            }
            if (inventory.contains(pid)) {
                auto &paths = candidates[pid];
                if (!paths.contains(path)) {
                    paths.append(path);
                }
            }
        }
    }
    // Membership can move while individual files are being read. Prefer the
    // independently sampled procfs path and never count a PID in two groups.
    for (auto it = candidates.cbegin(); it != candidates.cend(); ++it) {
        const auto process = inventory.value(it.key());
        const auto paths = it.value();
        QString selected;
        if (paths.contains(process.cgroup)) {
            selected = process.cgroup;
        } else if (paths.size() == 1) {
            selected = paths.first();
        } else {
            auto sorted = paths;
            sorted.sort();
            selected = sorted.first();
        }
        if (paths.size() > 1 || (!process.cgroup.isEmpty() && !paths.contains(process.cgroup))) {
            // The later membership files still prove this PID is in the desktop
            // scope. Do not drop foreign-UID helpers merely because the earlier
            // procfs path is stale. Mark the snapshot as raced, retain one
            // accounting membership, and never derive action rights from it.
            result.complete = false;
            result.issues.append(QStringLiteral("group-membership-changed"));
        }
        result.bindings.insert(process.pid, {applicationByPath.value(selected), process.startTime});
    }
    // An unreadable PID file must not drop readable processes whose procfs
    // membership still identifies a group that was discovered above.
    if (!result.complete) {
        mergeKernelGroups(result, desktopPath, processes);
    }
    result.issues.removeDuplicates();
    for (auto &app : result.applications) {
        app.origins.sort();
        app.origins.removeDuplicates();
    }
    return result;
}
