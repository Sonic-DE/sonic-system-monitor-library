/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include "application_resolver_p.h"

#include <KService>
#include <KShell>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStandardPaths>
#include <utility>

using namespace KSysGuard::ApplicationTracking;

namespace {
ProcessInfo statIdentity(qint64 pid, const QString &procRoot, bool includeName)
{
    ProcessInfo result;
    if (pid <= 1) {
        return result;
    }
    QFile stat(procRoot + QLatin1Char('/') + QString::number(pid) + QStringLiteral("/stat"));
    if (!stat.open(QIODevice::ReadOnly)) {
        return result;
    }
    const auto bytes = stat.read(16384);
    const auto endName = bytes.lastIndexOf(')');
    const auto beginName = bytes.indexOf('(');
    const auto fields = bytes.mid(endName + 2).simplified().split(' ');
    if (beginName < 0 || endName <= beginName || fields.size() <= 19 || bytes.left(beginName).trimmed().toLongLong() != pid) {
        return result;
    }
    bool valid = false;
    result.startTime = fields.at(19).toLongLong(&valid);
    if (!valid || result.startTime <= 0) {
        return {};
    }
    result.pid = pid;
    result.parentPid = fields.at(1).toLongLong();
    result.processGroupId = fields.at(2).toLongLong();
    result.sessionId = fields.at(3).toLongLong();
    if (includeName) {
        result.name = QString::fromUtf8(bytes.mid(beginName + 1, endName - beginName - 1));
    }
    return result;
}

std::pair<qint64, qint64> processOwnership(qint64 pid, const QString &procRoot)
{
    QFile status(procRoot + QLatin1Char('/') + QString::number(pid) + QStringLiteral("/status"));
    if (!status.open(QIODevice::ReadOnly)) {
        return {-1, -1};
    }
    for (const auto &line : status.read(65536).split('\n')) {
        if (!line.startsWith("Uid:")) {
            continue;
        }
        const auto ids = line.mid(4).simplified().split(' ');
        if (ids.size() < 2) {
            return {-1, -1};
        }
        bool uidValid = false;
        bool euidValid = false;
        const auto uid = ids.at(0).toLongLong(&uidValid);
        const auto euid = ids.at(1).toLongLong(&euidValid);
        return uidValid && euidValid && uid >= 0 && euid >= 0 ? std::pair<qint64, qint64>{uid, euid} : std::pair<qint64, qint64>{-1, -1};
    }
    return {-1, -1};
}

QString kernelGroupPath(qint64 pid, const QString &procRoot)
{
    QFile membership(procRoot + QLatin1Char('/') + QString::number(pid) + QStringLiteral("/cgroup"));
    QString result;
    if (!membership.open(QIODevice::ReadOnly)) {
        return result;
    }
    for (const auto &line : membership.read(65536).split('\n')) {
        const auto first = line.indexOf(':');
        const auto second = line.indexOf(':', first + 1);
        if (first < 0 || second < 0) {
            continue;
        }
        const auto controllers = line.mid(first + 1, second - first - 1);
        const auto path = QString::fromUtf8(line.mid(second + 1));
        if (!path.startsWith(QLatin1Char('/'))) {
            continue;
        }
        if (line.left(first) == "0") {
            return path;
        }
        if (result.isEmpty() || controllers.split(',').contains("name=systemd")) {
            result = path;
        }
    }
    return result;
}

QString canonicalExecutable(const QString &path)
{
    const QString resolved = path.startsWith(QLatin1Char('/')) ? path : QStandardPaths::findExecutable(path);
    return QFileInfo(resolved).canonicalFilePath();
}

bool sameIncarnation(const ProcessInfo &a, const ProcessInfo &b)
{
    return a.pid == b.pid && a.startTime > 0 && a.startTime == b.startTime && a.uid == b.uid && a.euid == b.euid && !a.executable.isEmpty()
        && a.executable == b.executable;
}

Application unknownApplication(const ProcessInfo &process, const QString &name)
{
    return {QStringLiteral("process:%1:%2").arg(process.pid).arg(process.startTime),
            name.isEmpty() ? process.name : name,
            QStringLiteral("application-x-executable"),
            {},
            isBoundaryExecutable(process.executable),
            isTerminalExecutable(process.executable)};
}

Application cgroupApplication(const QString &cgroup, const DesktopIndex &desktops)
{
    // Metadata only: no traversal of /sys/fs/cgroup and no assumed user root.
    // Accept only explicit application scopes with a known desktop identity;
    // never infer ownership from a session, background, or generic service.
    const auto components = cgroup.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (auto it = components.crbegin(); it != components.crend(); ++it) {
        auto component = *it;
        if (!component.endsWith(QLatin1String(".scope"))) {
            continue;
        }
        if (component.startsWith(QLatin1String("app-"))) {
            component.remove(0, 4);
        } else if (component.startsWith(QLatin1String("flatpak-"))) {
            component.remove(0, 8);
        } else {
            continue;
        }
        component.chop(6);
        const auto suffix = component.lastIndexOf(QLatin1Char('-'));
        if (suffix <= 0) {
            continue;
        }
        component.truncate(suffix);
        QByteArray decoded;
        const auto encoded = component.toUtf8();
        bool valid = true;
        for (int i = 0; i < encoded.size(); ++i) {
            if (encoded.at(i) != '\\') {
                decoded.append(encoded.at(i));
                continue;
            }
            bool ok = false;
            const auto character = encoded.mid(i + 2, 2).toUInt(&ok, 16);
            if (i + 3 >= encoded.size() || encoded.at(i + 1) != 'x' || !ok || character == 0 || character == '/') {
                valid = false;
                break;
            }
            decoded.append(char(character));
            i += 3;
        }
        if (!valid) {
            continue;
        }
        component = QString::fromUtf8(decoded);
        auto app = desktops.byId(component);
        if (app.id.isEmpty() && (component.startsWith(QLatin1String("KDE-")) || component.startsWith(QLatin1String("sonicde-")))) {
            app = desktops.byId(component.mid(component.indexOf(QLatin1Char('-')) + 1));
        }
        if (!app.id.isEmpty()) {
            return app;
        }
    }
    return {};
}
}

bool KSysGuard::ApplicationTracking::isTerminalExecutable(const QString &executable)
{
    static const QSet<QString> terminals = {QStringLiteral("konsole"),
                                            QStringLiteral("sonic-terminal"),
                                            QStringLiteral("xterm"),
                                            QStringLiteral("uxterm"),
                                            QStringLiteral("alacritty"),
                                            QStringLiteral("kitty"),
                                            QStringLiteral("foot"),
                                            QStringLiteral("wezterm-gui"),
                                            QStringLiteral("gnome-terminal-server"),
                                            QStringLiteral("xfce4-terminal"),
                                            QStringLiteral("yakuake")};
    return terminals.contains(QFileInfo(executable).fileName());
}

bool KSysGuard::ApplicationTracking::isBoundaryExecutable(const QString &executable)
{
    // Explicit attribution boundaries, not application identity heuristics.
    static const QSet<QString> names = {QStringLiteral("sh"),
                                        QStringLiteral("bash"),
                                        QStringLiteral("zsh"),
                                        QStringLiteral("fish"),
                                        QStringLiteral("dash"),
                                        QStringLiteral("konsole"),
                                        QStringLiteral("sonic-terminal"),
                                        QStringLiteral("xterm"),
                                        QStringLiteral("uxterm"),
                                        QStringLiteral("alacritty"),
                                        QStringLiteral("kitty"),
                                        QStringLiteral("foot"),
                                        QStringLiteral("wezterm-gui"),
                                        QStringLiteral("gnome-terminal-server"),
                                        QStringLiteral("xfce4-terminal"),
                                        QStringLiteral("tmux"),
                                        QStringLiteral("screen"),
                                        QStringLiteral("klauncher"),
                                        QStringLiteral("klauncher6"),
                                        QStringLiteral("kdeinit6"),
                                        QStringLiteral("dbus-daemon"),
                                        QStringLiteral("dbus-broker"),
                                        QStringLiteral("systemd"),
                                        QStringLiteral("env"),
                                        QStringLiteral("flatpak"),
                                        QStringLiteral("python"),
                                        QStringLiteral("python3"),
                                        QStringLiteral("perl"),
                                        QStringLiteral("ruby"),
                                        QStringLiteral("java"),
                                        QStringLiteral("node")};
    const auto name = QFileInfo(executable).fileName();
    return names.contains(name) || isTerminalExecutable(executable) || name.startsWith(QLatin1String("python3."));
}

void DesktopIndex::add(const Application &application, const QString &executable, const QString &windowClass, bool discoverByExecutable)
{
    if (application.id.isEmpty()) {
        return;
    }
    auto indexed = application;
    indexed.terminal = indexed.terminal || isTerminalExecutable(executable);
    indexed.boundary = indexed.boundary || indexed.terminal;
    m_applications.insert(application.id, indexed);
    if (discoverByExecutable && !executable.isEmpty()) {
        auto &ids = m_executables[executable];
        if (!ids.contains(application.id)) {
            ids.append(application.id);
        }
    }
    if (!windowClass.isEmpty()) {
        auto &ids = m_classes[windowClass.toLower()];
        if (!ids.contains(application.id)) {
            ids.append(application.id);
        }
    }
}

void DesktopIndex::reload()
{
    m_applications.clear();
    m_executables.clear();
    m_classes.clear();
    for (const auto &service : KService::allServices()) {
        if (!service->isApplication()) {
            continue;
        }
        KShell::Errors error;
        const auto args = KShell::splitArgs(service->exec(), KShell::AbortOnMeta, &error);
        const auto executable = error == KShell::NoError && !args.isEmpty() ? canonicalExecutable(args.first()) : QString();
        Application app{service->storageId(), service->name(), service->icon(), service->menuId(), isBoundaryExecutable(executable)};
        const auto categories = service->categories();
        app.terminal = isTerminalExecutable(executable) || categories.contains(QStringLiteral("TerminalEmulator"));
        app.boundary = app.boundary || app.terminal;
        // Hidden/terminal desktop entries are resolvable from an explicit window
        // ID, but their mere executable presence does not make them GUI apps.
        add(app,
            executable,
            service->property<QString>(QStringLiteral("StartupWMClass")),
            !service->noDisplay() && !service->terminal() && !isBoundaryExecutable(executable));
    }
}

Application DesktopIndex::byId(QString id) const
{
    if (m_applications.contains(id)) {
        return m_applications.value(id);
    }
    if (!id.endsWith(QLatin1String(".desktop"))) {
        id += QLatin1String(".desktop");
    }
    return m_applications.value(id);
}

Application DesktopIndex::byExecutable(const QString &executable) const
{
    const auto ids = m_executables.value(executable);
    return ids.size() == 1 ? m_applications.value(ids.first()) : Application{};
}

Application DesktopIndex::byWindowClass(const QString &windowClass) const
{
    const auto ids = m_classes.value(windowClass.toLower());
    return ids.size() == 1 ? m_applications.value(ids.first()) : Application{};
}

QMap<qint64, Assignment>
Resolver::resolve(const QList<ProcessInfo> &processes, qint64 uid, const QVariantList &hints, const DesktopIndex &desktops, const GroupCatalog &catalog)
{
    QMap<qint64, ProcessInfo> inventory;
    QMap<qint64, ProcessInfo> observed;
    for (const auto &process : processes) {
        if (process.pid > 1) {
            observed.insert(process.pid, process);
        }
        if (process.pid > 1 && process.uid == uid) {
            inventory.insert(process.pid, process);
        }
    }
    QMap<qint64, Assignment> assigned;
    QSet<qint64> conflicting;
    for (const auto &value : hints) {
        const auto hint = value.toMap();
        const auto pid = hint.value(QStringLiteral("pid")).toLongLong();
        const auto process = inventory.constFind(pid);
        if (process == inventory.cend() || process->startTime <= 0 || process->startTime != hint.value(QStringLiteral("startTime")).toLongLong()
            || process->executable.isEmpty() || conflicting.contains(pid)) {
            continue;
        }
        auto app = desktops.byId(hint.value(QStringLiteral("desktopId")).toString());
        if (app.id.isEmpty()) {
            app = desktops.byWindowClass(hint.value(QStringLiteral("windowClass")).toString());
        }
        if (app.id.isEmpty()) {
            // A real GUI process with no desktop entry still deserves a row,
            // but do not use window titles (documents) as application names.
            app = unknownApplication(*process, {});
        }
        if (assigned.contains(pid) && assigned.value(pid).application.id != app.id) {
            assigned.remove(pid);
            conflicting.insert(pid);
            continue;
        }
        app.boundary = app.boundary || isBoundaryExecutable(process->executable);
        app.terminal = app.terminal || isTerminalExecutable(process->executable);
        assigned.insert(pid, {*process, app, QStringLiteral("window")});
    }
    for (const auto &process : inventory) {
        if (assigned.contains(process.pid) || conflicting.contains(process.pid) || process.startTime <= 0 || process.executable.isEmpty()) {
            continue;
        }
        const auto app = desktops.byExecutable(process.executable);
        if (!app.id.isEmpty()) {
            assigned.insert(process.pid, {process, app, QStringLiteral("desktop executable")});
        } else if (const auto old = m_previous.constFind(process.pid);
                   old != m_previous.cend() && old->source == QLatin1String("window") && sameIncarnation(old->process, process)) {
            auto restored = *old;
            restored.process = process;
            assigned.insert(process.pid, restored);
        }
    }
    const auto identities = assigned;
    const bool exactDesktopScope = catalog.available && catalog.complete;
    if (exactDesktopScope) {
        assigned.clear();
    }
    for (auto it = catalog.bindings.cbegin(); it != catalog.bindings.cend(); ++it) {
        const auto process = observed.constFind(it.key());
        const auto app = catalog.applications.constFind(it->applicationId);
        if (process == observed.cend() || process->startTime != it->startTime || app == catalog.applications.cend()) {
            continue;
        }
        const auto identity = identities.constFind(it.key());
        const auto source = identity == identities.cend() ? QStringLiteral("group metadata") : identity->source;
        assigned.insert(it.key(), {*process, *app, source, false});
    }

    if (!exactDesktopScope) {
        QSet<QString> independentIds;
        for (const auto &identity : identities) {
            independentIds.insert(identity.application.id);
        }
        // Retain the existing narrowly scoped hint for detached helpers when a
        // full optional catalog is absent. Metadata never grants action rights.
        if (!catalog.available) {
            for (const auto &process : inventory) {
                if (assigned.contains(process.pid) || conflicting.contains(process.pid) || process.executable.isEmpty()) {
                    continue;
                }
                const auto app = cgroupApplication(process.cgroup, desktops);
                if (app.id.isEmpty() || !independentIds.contains(app.id)) {
                    continue;
                }
                bool conflict = false;
                auto parent = process.parentPid;
                for (int depth = 0; observed.contains(parent) && depth < 64; ++depth) {
                    const auto root = identities.constFind(parent);
                    if (root != identities.cend()) {
                        conflict = root->application.id != app.id || root->application.boundary;
                        break;
                    }
                    const auto &ancestor = observed[parent];
                    if (isBoundaryExecutable(ancestor.executable) || ancestor.uid != uid || ancestor.euid != process.euid) {
                        conflict = true;
                        break;
                    }
                    parent = ancestor.parentPid;
                    if (depth == 63) {
                        conflict = true;
                    }
                }
                if (!conflict) {
                    assigned.insert(process.pid, {process, app, QStringLiteral("application scope"), false});
                }
            }
        }
        const auto assignDescendants = [&] {
            QHash<qint64, Application> nearest;
            for (const auto &process : observed) {
                if (assigned.contains(process.pid)) {
                    continue;
                }
                QList<qint64> chain;
                QSet<qint64> visiting;
                auto current = process.pid;
                Application app;
                while (observed.contains(current) && !visiting.contains(current) && !conflicting.contains(current)) {
                    const auto known = assigned.constFind(current);
                    if (known != assigned.cend()) {
                        if (known->application.id != QLatin1String("services")) {
                            app = known->application;
                        }
                        break;
                    }
                    const auto cached = nearest.constFind(current);
                    if (cached != nearest.cend()) {
                        app = *cached;
                        break;
                    }
                    chain.append(current);
                    visiting.insert(current);
                    current = observed.value(current).parentPid;
                }
                for (const auto pid : chain) {
                    nearest.insert(pid, app);
                    if (!app.id.isEmpty()) {
                        assigned.insert(pid, {observed.value(pid), app, QStringLiteral("accounting ancestry"), false});
                    }
                }
            }
        };
        assignDescendants();
        // Prefer a newly identified ancestor first. Otherwise retain known
        // accounting across detachment, reparenting to a broker, and credential
        // changes for the same birth identity. Action rights are recomputed.
        for (const auto &process : observed) {
            if (assigned.contains(process.pid) || conflicting.contains(process.pid)) {
                continue;
            }
            const auto old = m_previous.constFind(process.pid);
            if (old != m_previous.cend() && process.startTime > 0 && old->application.id != QLatin1String("services")
                && old->process.startTime == process.startTime) {
                if ((old->source == QLatin1String("window") || old->source == QLatin1String("desktop executable")) && process.uid == old->process.uid
                    && !process.executable.isEmpty() && old->process.executable != process.executable) {
                    continue;
                }
                assigned.insert(process.pid, {process, old->application, QStringLiteral("accounting ancestry"), false});
            }
        }
        assignDescendants();

        // A standalone process-group leader is an init-independent service
        // boundary even without desktop metadata or a window. Do not collapse
        // identifiable headless services into one anonymous background row.
        static const QSet<QString> infrastructure = {QStringLiteral("systemd"),
                                                     QStringLiteral("dbus-daemon"),
                                                     QStringLiteral("dbus-broker"),
                                                     QStringLiteral("init"),
                                                     QStringLiteral("kdeinit6"),
                                                     QStringLiteral("klauncher"),
                                                     QStringLiteral("klauncher6"),
                                                     QStringLiteral("sshd"),
                                                     QStringLiteral("sh"),
                                                     QStringLiteral("bash"),
                                                     QStringLiteral("zsh"),
                                                     QStringLiteral("fish"),
                                                     QStringLiteral("dash")};
        for (const auto &process : inventory) {
            auto executableName = QFileInfo(process.executable).fileName();
            if (executableName.isEmpty()) {
                executableName = process.name;
            }
            if (!assigned.contains(process.pid) && !conflicting.contains(process.pid) && process.startTime > 0 && process.processGroupId == process.pid
                && !infrastructure.contains(executableName)) {
                assigned.insert(process.pid, {process, unknownApplication(process, {}), QStringLiteral("process group"), false});
            }
        }
        for (const auto &process : observed) {
            if (assigned.contains(process.pid) || process.processGroupId <= 1 || conflicting.contains(process.pid)) {
                continue;
            }
            const auto leader = assigned.constFind(process.processGroupId);
            if (leader != assigned.cend() && leader->application.id != QLatin1String("services") && leader->process.processGroupId == leader->process.pid
                && leader->process.sessionId > 0 && process.sessionId == leader->process.sessionId) {
                assigned.insert(process.pid, {process, leader->application, QStringLiteral("process group"), false});
            }
        }
        assignDescendants();
        for (const auto &process : inventory) {
            if (!assigned.contains(process.pid)) {
                assigned.insert(process.pid,
                                {process,
                                 {QStringLiteral("services"), {}, QStringLiteral("preferences-system-services"), QStringLiteral("services"), true},
                                 QStringLiteral("unclassified"),
                                 false});
            }
        }
    }

    // Independently verified identities and same-credential ancestry determine
    // action rights, separately from the broader information/accounting set.
    QSet<QString> terminalGroups;
    QMap<qint64, bool> controllable;
    for (const auto &identity : identities) {
        auto member = assigned.find(identity.process.pid);
        if (member == assigned.end()) {
            continue;
        }
        if (identity.application.terminal) {
            terminalGroups.insert(member->application.id);
        }
        const auto &p = member->process;
        if (p.startTime > 0 && p.uid == uid && p.euid == uid && !p.executable.isEmpty() && member->application.id != QLatin1String("services")) {
            controllable.insert(p.pid, true);
        }
    }
    for (auto &member : assigned) {
        if (terminalGroups.contains(member.application.id)) {
            member.application.terminal = true;
            member.application.boundary = true;
        }
        const auto &p = member.process;
        if (controllable.contains(p.pid)) {
            continue;
        }
        if (member.application.id == QLatin1String("services") || p.startTime <= 0 || p.uid != uid || p.euid != uid || p.executable.isEmpty()
            || member.application.terminal || isBoundaryExecutable(p.executable) || conflicting.contains(p.pid)) {
            controllable.insert(p.pid, false);
            continue;
        }
        const auto old = m_previous.constFind(p.pid);
        if (!observed.contains(p.parentPid) && old != m_previous.cend() && old->actionEligible && old->application.id == member.application.id
            && sameIncarnation(old->process, p)) {
            controllable.insert(p.pid, true);
        }
    }
    for (const auto &member : std::as_const(assigned)) {
        const auto pid = member.process.pid;
        if (controllable.contains(pid)) {
            continue;
        }
        QList<qint64> chain;
        QSet<qint64> visiting;
        auto current = pid;
        bool allowed = false;
        while (assigned.contains(current) && !visiting.contains(current)) {
            const auto &ancestor = assigned[current];
            if (ancestor.application.id != member.application.id) {
                break;
            }
            if (controllable.contains(current)) {
                allowed = controllable.value(current) && !ancestor.application.boundary && !isBoundaryExecutable(ancestor.process.executable);
                break;
            }
            chain.append(current);
            visiting.insert(current);
            current = ancestor.process.parentPid;
        }
        for (const auto child : chain) {
            controllable.insert(child, allowed);
        }
    }
    for (auto &member : assigned) {
        member.actionEligible = controllable.value(member.process.pid, false);
    }
    m_previous = assigned;
    return assigned;
}

void Resolver::clear()
{
    m_previous.clear();
}

QString KSysGuard::ApplicationTracking::readExecutable(qint64 pid, const QString &procRoot)
{
    if (pid <= 1) {
        return {};
    }
    return QFileInfo(procRoot + QLatin1Char('/') + QString::number(pid) + QStringLiteral("/exe")).symLinkTarget();
}

ProcessInfo KSysGuard::ApplicationTracking::readProcess(qint64 pid, const QString &procRoot)
{
    auto result = statIdentity(pid, procRoot, true);
    if (result.pid <= 1) {
        return {};
    }
    const auto [uid, euid] = processOwnership(pid, procRoot);
    result.uid = uid;
    result.euid = euid;
    if (result.uid < 0 || result.euid < 0) {
        return {};
    }
    result.pid = pid;
    result.executable = readExecutable(pid, procRoot);
    result.cgroup = kernelGroupPath(pid, procRoot);
    return result;
}

ProcessInfo KSysGuard::ApplicationTracking::readProcessGroupIdentity(qint64 pid, const QString &procRoot)
{
    auto result = statIdentity(pid, procRoot, false);
    if (result.pid > 1) {
        const auto [uid, euid] = processOwnership(pid, procRoot);
        result.uid = uid;
        result.euid = euid;
        result.cgroup = kernelGroupPath(pid, procRoot);
    }
    return result;
}

QList<ProcessInfo> KSysGuard::ApplicationTracking::readProcessInventory(const QString &procRoot)
{
    QList<ProcessInfo> result;
    const auto entries = QDir(procRoot).entryList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks);
    for (const auto &entry : entries) {
        bool numeric = false;
        const auto pid = entry.toLongLong(&numeric);
        if (!numeric || pid <= 1) {
            continue;
        }
        const auto process = readProcess(pid, procRoot);
        if (process.pid > 1) {
            result.append(process);
        } else if (QFileInfo(procRoot + QLatin1Char('/') + entry).isDir()) {
            // Numeric process directories can be visible while identity files
            // are denied. A trusted group can still account for this PID, but
            // without a birth identity it can never become an action target.
            auto opaque = statIdentity(pid, procRoot, false);
            opaque.pid = pid;
            const auto [uid, euid] = processOwnership(pid, procRoot);
            opaque.uid = uid;
            opaque.euid = euid;
            opaque.cgroup = kernelGroupPath(pid, procRoot);
            result.append(opaque);
        }
    }
    return result;
}
