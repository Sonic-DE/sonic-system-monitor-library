/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include <KUser>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QPersistentModelIndex>
#include <QTemporaryDir>
#include <QTest>
#include <QThreadPool>
#include <map>
#include <memory>

#include "processcore/application_data_model.h"
#include "processcore/application_process_model.h"
#include "processcore/application_resolver_p.h"
#include "processcore/cgroup.h"
#include "processcore/process.h"
#include "processcore/process_data_model.h"

using namespace KSysGuard;
using namespace KSysGuard::ApplicationTracking;

namespace {
struct RowSnapshot {
    QSet<qint64> pids;
    QStringList origins;
    QString name;
};

struct DiscoverySnapshot {
    QMap<QString, RowSnapshot> rows;
    QSet<qint64> pids;
    int visibleRows = 0;
    bool duplicatePid = false;
};

// Actual procfs-like directories and cgroup.procs files, not lists passed to
// either model's processesFor(). Each implementation discovers membership from
// its own production path. No test PID is ever sent a signal or scheduling call.
class DiscoveryFixture {
public:
    QTemporaryDir directory;
    const qint64 uid = KUserId::currentEffectiveUserId().nativeId();
    QString error;
    std::map<qint64, std::unique_ptr<Process>> samples;

    DiscoveryFixture()
    {
        makeDirectory(procRoot());
        makeDirectory(groupRoot() + desktopPath());
        write(groupRoot() + desktopPath() + QStringLiteral("/cgroup.procs"), {});
    }
    QString procRoot() const
    {
        return directory.filePath(QStringLiteral("proc"));
    }
    QString groupRoot() const
    {
        return directory.filePath(QStringLiteral("groups"));
    }
    QString desktopPath() const
    {
        return QStringLiteral("/user.slice/user-%1.slice/user@%1.service").arg(uid);
    }
    QString groupPath(const QString &relative) const
    {
        return desktopPath() + QLatin1Char('/') + relative;
    }

    void makeDirectory(const QString &path)
    {
        if (!QDir().mkpath(path)) {
            error = QStringLiteral("Cannot create %1").arg(path);
        }
    }
    void write(const QString &path, const QByteArray &bytes)
    {
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate) || file.write(bytes) != bytes.size()) {
            error = QStringLiteral("Cannot write %1: %2").arg(path, file.errorString());
        }
    }
    void group(const QString &relative, const QList<qint64> &pids)
    {
        const auto path = groupRoot() + groupPath(relative);
        makeDirectory(path);
        QByteArray content;
        for (auto pid : pids) {
            content += QByteArray::number(pid) + '\n';
        }
        write(path + QStringLiteral("/cgroup.procs"), content);
    }
    void process(qint64 pid,
                 qint64 parent,
                 qint64 realUid,
                 qint64 effectiveUid,
                 const QString &name,
                 const QString &group,
                 qint64 processGroup = -1,
                 qint64 session = -1,
                 qint64 birth = -1,
                 bool readableExecutable = true)
    {
        const auto path = procRoot() + QLatin1Char('/') + QString::number(pid);
        makeDirectory(path);
        QByteArrayList fields;
        for (int i = 0; i < 20; ++i) {
            fields.append("0");
        }
        fields[0] = "S";
        fields[1] = QByteArray::number(parent);
        fields[2] = QByteArray::number(processGroup);
        fields[3] = QByteArray::number(session);
        fields[19] = QByteArray::number(birth > 0 ? birth : pid * 10);
        write(path + QStringLiteral("/stat"), QByteArray::number(pid) + " (" + name.toUtf8() + ") " + fields.join(' ') + '\n');
        write(path + QStringLiteral("/status"), "Uid:\t" + QByteArray::number(realUid) + '\t' + QByteArray::number(effectiveUid) + "\t0\t0\n");
        write(path + QStringLiteral("/cgroup"), "0::" + group.toUtf8() + '\n');
        QFile::remove(path + QStringLiteral("/exe"));
        if (readableExecutable) {
            const auto executable = directory.filePath(QStringLiteral("executables/%1").arg(name.isEmpty() ? QString::number(pid) : name));
            makeDirectory(QFileInfo(executable).path());
            write(executable, {});
            if (!QFile::link(executable, path + QStringLiteral("/exe"))) {
                error = QStringLiteral("Cannot link executable for %1").arg(pid);
            }
        }
    }
    Process *lookup(qint64 pid)
    {
        auto info = readProcess(pid, procRoot());
        if (info.pid <= 1) {
            if (!QFileInfo(procRoot() + QLatin1Char('/') + QString::number(pid)).isDir()) {
                return nullptr;
            }
            info.pid = pid;
        }
        auto &sample = samples[pid];
        if (!sample) {
            sample = std::make_unique<Process>(pid, info.parentPid, nullptr);
        }
        sample->setParentPid(info.parentPid);
        sample->setStartTime(info.startTime);
        sample->setUid(info.uid);
        sample->setEuid(info.euid);
        sample->setName(info.name);
        sample->setCGroup(info.cgroup);
        return sample.get();
    }
    void removeProcess(qint64 pid)
    {
        if (!QDir(procRoot() + QLatin1Char('/') + QString::number(pid)).removeRecursively()) {
            error = QStringLiteral("Cannot remove process");
        }
    }
    void removeGroup(const QString &relative)
    {
        if (!QDir(groupRoot() + groupPath(relative)).removeRecursively()) {
            error = QStringLiteral("Cannot remove group");
        }
    }
};

// This is the original QML mapping, kept explicitly in the legacy oracle rather
// than reusing the new catalog's classifier. Errors in the new rules therefore
// show up as actual old-only/new-only groups or PIDs.
QVariantMap legacyMapping()
{
    QVariantMap result;
    const QStringList fragments = {QStringLiteral("session.slice"),
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
    for (const auto &fragment : fragments) {
        result.insert(fragment, QStringLiteral("services"));
    }
    return result;
}

QVariantMap overrides()
{
    return {{QStringLiteral("services"),
             QVariantMap{{QStringLiteral("appName"), QStringLiteral("Background Services")},
                         {QStringLiteral("iconName"), QStringLiteral("preferences-system-services")},
                         {QStringLiteral("menuId"), QStringLiteral("services")}}}};
}

void addPids(DiscoverySnapshot &snapshot, RowSnapshot &row, const QVariantList &values)
{
    for (const auto &value : values) {
        const auto pid = value.toLongLong();
        snapshot.duplicatePid = snapshot.duplicatePid || snapshot.pids.contains(pid);
        snapshot.pids.insert(pid);
        row.pids.insert(pid);
    }
    if (!row.pids.isEmpty()) {
        ++snapshot.visibleRows;
    }
}

bool equivalent(const DiscoverySnapshot &old, const DiscoverySnapshot &current, QString &error)
{
    if (old.rows.keys() != current.rows.keys()) {
        error = QStringLiteral("Group mismatch: old=[%1] new=[%2]").arg(old.rows.keys().join(QLatin1Char(',')), current.rows.keys().join(QLatin1Char(',')));
        return false;
    }
    for (auto it = old.rows.cbegin(); it != old.rows.cend(); ++it) {
        const auto row = current.rows.value(it.key());
        if (it->pids != row.pids || it->origins != row.origins || it->name != row.name) {
            error = QStringLiteral("Membership, origins, or label mismatch for %1").arg(it.key());
            return false;
        }
    }
    if (old.pids != current.pids || old.visibleRows != current.visibleRows || current.duplicatePid) {
        error = QStringLiteral("Total PID/visible group mismatch or duplicate accounting");
        return false;
    }
    return true;
}
}

class ApplicationDiscoveryTest : public QObject {
    Q_OBJECT

    bool legacySnapshot(DiscoveryFixture &fixture, DiscoverySnapshot &snapshot)
    {
        ApplicationDataModel legacy;
        legacy.setDiscoverySource(fixture.groupRoot(), [&fixture](qint64 pid) {
            return fixture.lookup(pid);
        });
        legacy.setCGroupMapping(legacyMapping());
        legacy.setApplicationOverrides(overrides());
        legacy.setEnabledAttributes({QStringLiteral("appName"), QStringLiteral("menuId")});
        return captureLegacy(legacy, snapshot);
    }

    bool captureLegacy(ApplicationDataModel &legacy, DiscoverySnapshot &snapshot)
    {
        legacy.update();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        if (!QThreadPool::globalInstance()->waitForDone(5000)) {
            return false;
        }
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        if (!legacy.isAvailable()) {
            return false;
        }
        snapshot = {};
        for (int row = 0; row < legacy.rowCount(); ++row) {
            const auto index = legacy.index(row, 0, {});
            auto *group = static_cast<CGroup *>(index.internalPointer());
            const auto id = legacy.applicationId(group);
            auto &record = snapshot.rows[id];
            record.name = legacy.data(index, ProcessDataModel::Value).toString();
            for (auto *origin : legacy.m_applications.value(id).cgroups) {
                record.origins.append(origin->id());
            }
            record.origins.sort();
            addPids(snapshot, record, legacy.data(index, ProcessDataModel::PIDs).toList());
        }
        return true;
    }

    bool liveLegacySnapshot(DiscoverySnapshot &snapshot)
    {
        ApplicationDataModel legacy;
        legacy.setEnabled(false);
        legacy.setCGroupMapping(legacyMapping());
        legacy.setApplicationOverrides(overrides());
        legacy.setEnabledAttributes({QStringLiteral("appName"), QStringLiteral("menuId")});
        return captureLegacy(legacy, snapshot);
    }

    DiscoverySnapshot visibleSnapshot(DiscoverySnapshot snapshot)
    {
        for (auto it = snapshot.rows.begin(); it != snapshot.rows.end();) {
            if (it->pids.isEmpty()) {
                it = snapshot.rows.erase(it);
            } else {
                // Empty physical units can be created/collected between live
                // reads without changing any information visible in the view.
                // Static fixture comparisons still require exact physical origins.
                it->origins.clear();
                ++it;
            }
        }
        return snapshot;
    }

    DiscoverySnapshot currentSnapshot(ApplicationProcessModel &model)
    {
        DiscoverySnapshot snapshot;
        for (int row = 0; row < model.rowCount(); ++row) {
            const auto index = model.index(row, 0);
            const auto id = index.data(ApplicationProcessModel::ApplicationId).toString();
            auto &record = snapshot.rows[id];
            record.name = index.data(ProcessDataModel::Value).toString();
            record.origins = index.data(ApplicationProcessModel::GroupOrigins).toStringList();
            addPids(snapshot, record, index.data(ProcessDataModel::PIDs).toList());
        }
        return snapshot;
    }

    void configure(ApplicationProcessModel &model, DiscoveryFixture &fixture)
    {
        model.setDiscoveryRoots(fixture.procRoot(), fixture.groupRoot());
        model.setProcessLookup([&fixture](qint64 pid) {
            return fixture.lookup(pid);
        });
        model.setApplicationOverrides(overrides());
        model.setEnabledAttributes({QStringLiteral("appName"), QStringLiteral("menuId")});
    }

    void populate(DiscoveryFixture &f)
    {
        const auto editor = QStringLiteral("app.slice/app-org.test.Editor-a.scope");
        const auto second = QStringLiteral("app.slice/app-org.test.Editor@b.service");
        const auto unknown = QStringLiteral("app.slice/app-UnknownTool-a.scope");
        const auto daemon = QStringLiteral("app.slice/app-daemon@a.service");
        const auto sandbox = QStringLiteral("app.slice/flatpak-org.test.Sandbox-a.scope");
        const auto sandboxWorker = sandbox + QStringLiteral("/worker.scope");
        const auto ignored = sandbox + QStringLiteral("/worker.service");
        const auto session = QStringLiteral("session.slice/pipewire.service");
        const auto background = QStringLiteral("background.slice/worker.service");
        const auto wallet = QStringLiteral("app.slice/app-org.kde.kwalletd6-a.scope");
        f.group(editor, {100, 101, 104, 105, 9999}); // Nonexistent PID 9999 must not be counted.
        f.group(second, {102});
        f.group(unknown, {110});
        f.group(daemon, {120, 121});
        f.group(sandbox, {130});
        f.group(sandboxWorker, {131});
        f.group(ignored, {132});
        f.group(session, {140});
        f.group(background, {141});
        f.group(wallet, {142});
        f.group(QStringLiteral("app.slice/app-org.test.Empty-a.scope"), {});
        f.group(QStringLiteral("control.slice/unmapped.service"), {150});
        const auto u = f.uid;
        f.process(100, 1, u, u, QStringLiteral("Editor"), f.groupPath(editor), 100, 100);
        f.process(101, 100, u, u, QStringLiteral("helper"), f.groupPath(editor), 100, 100);
        f.process(102, 1, u, u, QStringLiteral("Editor"), f.groupPath(second), 102, 102);
        f.process(104, 100, u + 1, u + 1, QStringLiteral("privileged"), f.groupPath(editor), 100, 100, -1, false);
        f.process(105, 1, u + 1, u + 1, QStringLiteral("detached"), f.groupPath(editor), 100, 100, -1, false);
        f.process(110, 1, u, u, QStringLiteral("UnknownTool"), f.groupPath(unknown), 110, 110, -1, false);
        f.process(120, 1, u, u, QStringLiteral("daemon"), f.groupPath(daemon), 120, 120);
        f.process(121, 120, u + 1, u + 1, QStringLiteral("daemon-helper"), f.groupPath(daemon), 120, 120, -1, false);
        f.process(130, 1, u, u, QStringLiteral("Sandbox"), f.groupPath(sandbox), 130, 130);
        f.process(131, 130, u, u, QStringLiteral("sandbox-helper"), f.groupPath(sandboxWorker), 130, 130);
        f.process(132, 130, u, u, QStringLiteral("legacy-excluded"), f.groupPath(ignored), 130, 130);
        f.process(140, 1, u, u, QStringLiteral("pipewire"), f.groupPath(session), 140, 140);
        f.process(141, 140, u + 1, u + 1, QStringLiteral("worker"), f.groupPath(background), 140, 140, -1, false);
        f.process(142, 1, u, u, QStringLiteral("wallet"), f.groupPath(wallet), 142, 142);
        f.process(150, 1, u, u, QStringLiteral("unmapped"), f.groupPath(QStringLiteral("control.slice/unmapped.service")), 150, 150);
        f.process(152, 1, u, u, QStringLiteral("outside-desktop"), QStringLiteral("/outside"), 152, 152);
        f.process(153, 1, u + 1, u + 1, QStringLiteral("foreign-daemon"), QStringLiteral("/other-user"), 153, 153);
    }

private Q_SLOTS:
    void initTestCase()
    {
        QCoreApplication::addLibraryPath(QStringLiteral(APPLICATION_TEST_PLUGIN_PATH));
    }

    void liveSessionDiscoveryMatchesLegacy()
    {
        if (!qEnvironmentVariableIsSet("SONIC_MONITOR_LIVE_COMPARE")) {
            QSKIP("Opt in to this read-only live-session comparison with SONIC_MONITOR_LIVE_COMPARE=1");
        }
        ApplicationProcessModel model;
        model.setApplicationOverrides(overrides());
        model.setEnabledAttributes({QStringLiteral("appName"), QStringLiteral("menuId")});
        QString error;
        for (int attempt = 0; attempt < 3; ++attempt) {
            DiscoverySnapshot before, after;
            QVERIFY2(liveLegacySnapshot(before), "The live legacy desktop scope is unavailable or its PID reads did not complete");
            QVERIFY2(!before.pids.isEmpty(), "The live legacy scope contains no processes; an empty comparison is not meaningful validation");
            model.update();
            QVERIFY(model.available());
            const auto current = visibleSnapshot(currentSnapshot(model));
            QVERIFY(liveLegacySnapshot(after));
            const auto baseline = visibleSnapshot(before);
            const auto bracket = visibleSnapshot(after);
            qInfo() << "Live comparison attempt" << attempt + 1 << "legacy PIDs/groups" << baseline.pids.size() << baseline.visibleRows << "new PIDs/groups"
                    << current.pids.size() << current.visibleRows;
            if (before.duplicatePid || after.duplicatePid || !equivalent(baseline, bracket, error)) {
                error = QStringLiteral("Legacy scope changed during the A/B/A capture");
                qInfo().noquote() << error;
                continue;
            }
            if (equivalent(baseline, current, error)) {
                qInfo() << "Exact live PID-set and visible-group membership parity established";
                return;
            }
            qInfo() << "Old-only PIDs" << (baseline.pids - current.pids) << "new-only PIDs" << (current.pids - baseline.pids);
            const auto ids = QSet<QString>(baseline.rows.keyBegin(), baseline.rows.keyEnd()) | QSet<QString>(current.rows.keyBegin(), current.rows.keyEnd());
            for (const auto &id : ids) {
                if (!baseline.rows.contains(id) || !current.rows.contains(id) || baseline.rows.value(id).pids != current.rows.value(id).pids) {
                    qInfo() << "Group" << id << "legacy PIDs" << baseline.rows.value(id).pids << "new PIDs" << current.rows.value(id).pids;
                }
            }
        }
        QFAIL(qPrintable(error));
    }

    void legacyPidAndGroupDiscoveryAreEqual()
    {
        DiscoveryFixture fixture;
        populate(fixture);
        QVERIFY2(fixture.error.isEmpty(), qPrintable(fixture.error));
        DiscoverySnapshot legacy;
        QVERIFY(legacySnapshot(fixture, legacy));
        ApplicationProcessModel model;
        configure(model, fixture);
        const auto editorIdentity = readProcess(100, fixture.procRoot());
        model.setIdentityHints({QVariantMap{{QStringLiteral("pid"), 100}, {QStringLiteral("startTime"), QString::number(editorIdentity.startTime)}}});
        model.update();
        const auto current = currentSnapshot(model);
        QString error;
        QVERIFY2(equivalent(legacy, current, error), qPrintable(error));
        QCOMPARE(current.rows.size(), 6);
        QCOMPARE(current.visibleRows, 5);
        QCOMPARE(current.pids.size(), 13);
        QSet<QString> physicalGroups;
        for (const auto &row : current.rows) {
            for (const auto &origin : row.origins) {
                physicalGroups.insert(origin);
            }
        }
        QCOMPARE(physicalGroups.size(), 10);
        QVERIFY(!current.pids.contains(132));
        QVERIFY(!current.pids.contains(150));
        QVERIFY(!current.pids.contains(152));
        QVERIFY(!current.pids.contains(153));
        QVERIFY(!current.pids.contains(9999));
        QVERIFY(current.rows.value(QStringLiteral("UnknownTool")).pids.contains(110));
        QVERIFY(current.rows.value(QStringLiteral("org.test.Editor")).pids.contains(104));
        QVERIFY(current.rows.value(QStringLiteral("org.test.Editor")).pids.contains(105));
        QVERIFY(current.rows.value(QStringLiteral("daemon")).pids.contains(121));
        const auto targets = model.captureTargets({QStringLiteral("org.test.Editor")});
        QSet<qint64> direct;
        for (const auto &target : targets) {
            direct.insert(target.toMap().value(QStringLiteral("pid")).toLongLong());
        }
        QCOMPARE(direct, QSet<qint64>({100, 101}));
        QVERIFY(model.captureTargets({QStringLiteral("services")}).isEmpty());
    }

    void everyLegacyBackgroundServiceMappingIsPreserved()
    {
        DiscoveryFixture fixture;
        qint64 pid = 200;
        const auto mappings = legacyMapping();
        for (auto it = mappings.cbegin(); it != mappings.cend(); ++it, ++pid) {
            auto fragment = it.key();
            if (fragment == QLatin1String("org.kde.kwalletd6")) {
                fragment = fragment.toUpper();
            }
            QString relative;
            if (fragment.endsWith(QLatin1String(".slice"))) {
                relative = fragment + QStringLiteral("/fixture-%1.service").arg(pid);
            } else if (fragment.endsWith(QLatin1String(".service"))) {
                relative = QStringLiteral("app.slice/") + fragment;
            } else {
                relative = QStringLiteral("app.slice/app-%1-fixture.scope").arg(fragment);
            }
            fixture.group(relative, {pid});
            fixture.process(pid, 1, fixture.uid, fixture.uid, QStringLiteral("background-worker"), fixture.groupPath(relative), pid, pid);
        }
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        ApplicationProcessModel model;
        configure(model, fixture);
        model.update();
        const auto current = currentSnapshot(model);
        QString error;
        QVERIFY2(equivalent(old, current, error), qPrintable(error));
        QCOMPARE(current.visibleRows, 1);
        QCOMPARE(current.rows.size(), 1);
        QCOMPARE(current.pids.size(), mappings.size());
        QCOMPARE(current.rows.value(QStringLiteral("services")).origins.size(), mappings.size());
        QVERIFY(model.captureTargets({QStringLiteral("services")}).isEmpty());
        QVERIFY2(fixture.error.isEmpty(), qPrintable(fixture.error));
    }

    void lifecycleMatchesFreshLegacyDiscovery()
    {
        DiscoveryFixture fixture;
        populate(fixture);
        ApplicationProcessModel model;
        configure(model, fixture);
        const auto compare = [&] {
            model.update();
            DiscoverySnapshot old;
            if (!legacySnapshot(fixture, old)) {
                return QStringLiteral("Legacy discovery did not finish");
            }
            QString error;
            equivalent(old, currentSnapshot(model), error);
            return error;
        };
        auto error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QPersistentModelIndex editor(model.index(model.rowForApplication(QStringLiteral("org.test.Editor")), 0));
        const auto main = QStringLiteral("app.slice/app-org.test.Editor-a.scope");
        fixture.process(103, 100, fixture.uid, fixture.uid, QStringLiteral("new-helper"), fixture.groupPath(main), 100, 100);
        fixture.group(main, {100, 101, 103, 104, 105});
        error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QVERIFY(editor.isValid());

        fixture.process(100, 1, fixture.uid + 1, fixture.uid + 1, QStringLiteral("Editor"), fixture.groupPath(main), 100, 100, -1, false);
        fixture.process(103, 1, fixture.uid + 1, fixture.uid + 1, QStringLiteral("new-helper"), fixture.groupPath(main), 100, 100, -1, false);
        error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QVERIFY(model.captureTargets({QStringLiteral("org.test.Editor")}).isEmpty());

        fixture.removeProcess(101);
        fixture.group(main, {100, 102, 103, 104, 105});
        fixture.process(102, 1, fixture.uid, fixture.uid, QStringLiteral("Editor"), fixture.groupPath(main), 102, 102);
        fixture.removeGroup(QStringLiteral("app.slice/app-org.test.Editor@b.service"));
        error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QVERIFY(editor.isValid());

        fixture.group(main, {100, 102, 104, 105});
        const auto unknown = QStringLiteral("app.slice/app-UnknownTool-a.scope");
        fixture.group(unknown, {103, 110});
        fixture.process(103, 1, fixture.uid, fixture.uid, QStringLiteral("replacement"), fixture.groupPath(unknown), 103, 103, 77777);
        error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QVERIFY(currentSnapshot(model).rows.value(QStringLiteral("UnknownTool")).pids.contains(103));

        fixture.removeProcess(103);
        fixture.removeProcess(110);
        fixture.group(unknown, {});
        error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        const auto empty = currentSnapshot(model);
        QVERIFY(empty.rows.contains(QStringLiteral("UnknownTool")));
        QVERIFY(empty.rows.value(QStringLiteral("UnknownTool")).pids.isEmpty());
        fixture.removeGroup(unknown);
        error = compare();
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QVERIFY(!currentSnapshot(model).rows.contains(QStringLiteral("UnknownTool")));
        QVERIFY2(fixture.error.isEmpty(), qPrintable(fixture.error));
    }

    void missingMetadataDoesNotRequireSystemdOrLoseProcesses()
    {
        DiscoveryFixture fixture;
        const auto u = fixture.uid;
        const auto editor = QStringLiteral("app.slice/app-GapEditor-a.scope");
        const auto indexer = QStringLiteral("app.slice/app-GapIndexer-a.scope");
        const auto watcher = QStringLiteral("app.slice/app-GapWatcher-a.scope");
        const auto background = QStringLiteral("background.slice/generic.service");
        fixture.group(editor, {100, 101, 102});
        fixture.group(indexer, {200, 201});
        fixture.group(watcher, {210});
        fixture.group(background, {220});
        fixture.process(100, 1, u, u, QStringLiteral("GapEditor"), fixture.groupPath(editor), 100, 100);
        fixture.process(101, 100, u + 1, u + 1, QStringLiteral("helper"), fixture.groupPath(editor), 100, 100, -1, false);
        fixture.process(102, 1, u + 1, u + 1, QStringLiteral("detached"), fixture.groupPath(editor), 100, 100, -1, false);
        fixture.process(200, 1, u, u, QStringLiteral("GapIndexer"), fixture.groupPath(indexer), 200, 200);
        fixture.process(201, 1, u + 1, u + 1, QStringLiteral("index-helper"), fixture.groupPath(indexer), 200, 200, -1, false);
        fixture.process(210, 1, u, u, QStringLiteral("GapWatcher"), fixture.groupPath(watcher), 210, 210);
        fixture.process(220, 1, u, u, QString(), fixture.groupPath(background), -1, -1, -1, false);
        fixture.process(230, 1, u + 1, u + 1, QStringLiteral("foreign"), QStringLiteral("/unrelated"), 230, 230, -1, false);
        const auto privatePeer = readProcessGroupIdentity(102, fixture.procRoot());
        QCOMPARE(privatePeer.parentPid, 1);
        QCOMPARE(privatePeer.processGroupId, 100);
        QCOMPARE(privatePeer.sessionId, 100);
        QCOMPARE(privatePeer.uid, u + 1);
        QCOMPARE(privatePeer.euid, u + 1);
        QVERIFY(privatePeer.name.isEmpty());
        QVERIFY(privatePeer.executable.isEmpty());
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        QVERIFY(QDir(fixture.groupRoot()).removeRecursively());
        fixture.makeDirectory(fixture.groupRoot());
        for (const auto &process : readProcessInventory(fixture.procRoot())) {
            QVERIFY(QFile::remove(fixture.procRoot() + QLatin1Char('/') + QString::number(process.pid) + QStringLiteral("/cgroup")));
        }
        ApplicationProcessModel model; // Cold start: no cached legacy grouping.
        configure(model, fixture);
        model.update();
        const auto current = currentSnapshot(model);
        QVERIFY(model.available());
        QCOMPARE(current.pids, old.pids);
        QCOMPARE(current.visibleRows, old.visibleRows);
        QVERIFY(!current.duplicatePid);
        QMap<QString, QSet<qint64>> oldNames, currentNames;
        for (const auto &row : old.rows) {
            if (!row.pids.isEmpty()) {
                oldNames.insert(row.name, row.pids);
            }
        }
        for (const auto &row : current.rows) {
            if (!row.pids.isEmpty()) {
                currentNames.insert(row.name, row.pids);
            }
        }
        QCOMPARE(currentNames, oldNames);
        QVERIFY(!current.pids.contains(230));
        for (int row = 0; row < model.rowCount(); ++row) {
            QVERIFY(model.index(row, 0).data(ApplicationProcessModel::ActionPIDs).toList().isEmpty());
        }
        QVERIFY2(fixture.error.isEmpty(), qPrintable(fixture.error));
    }

    void incompleteMetadataKeepsCoverageAndReportsIt()
    {
        DiscoveryFixture fixture;
        populate(fixture);
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        const auto path = fixture.groupRoot() + fixture.groupPath(QStringLiteral("app.slice/app-org.test.Editor-a.scope")) + QStringLiteral("/cgroup.procs");
        QVERIFY(QFile::remove(path));
        ApplicationProcessModel model;
        configure(model, fixture);
        model.update();
        const auto current = currentSnapshot(model);
        QVERIFY(model.available());
        QVERIFY(!model.statusMessage().isEmpty());
        QVERIFY((old.pids - current.pids).isEmpty());
        QCOMPARE(current.rows.value(QStringLiteral("org.test.Editor")).pids, old.rows.value(QStringLiteral("org.test.Editor")).pids);
        QVERIFY(!current.duplicatePid);
    }

    void procMembershipPreservesUnknownGroupsWithoutGroupMount()
    {
        DiscoveryFixture fixture;
        populate(fixture);
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        // These processes were never in the legacy desktop scope. Remove them
        // from this corpus so broad fallback coverage cannot mask missing PIDs.
        fixture.removeProcess(132);
        fixture.removeProcess(150);
        fixture.removeProcess(152);
        QVERIFY(QDir(fixture.groupRoot()).removeRecursively());
        fixture.makeDirectory(fixture.groupRoot());
        ApplicationProcessModel model; // No cached groups and no group mount.
        configure(model, fixture);
        model.update();
        const auto current = currentSnapshot(model);
        QCOMPARE(current.pids, old.pids);
        QCOMPARE(current.visibleRows, old.visibleRows);
        QVERIFY(!current.duplicatePid);
        for (auto it = old.rows.cbegin(); it != old.rows.cend(); ++it) {
            if (it->pids.isEmpty()) {
                continue;
            } // The old UI hides these too.
            const auto found = current.rows.constFind(it.key());
            QVERIFY2(found != current.rows.cend(), qPrintable(it.key()));
            QCOMPARE(found->pids, it->pids);
            QCOMPARE(found->name, it->name);
            QCOMPARE(found->origins, it->origins);
        }
        QVERIFY(model.captureTargets({QStringLiteral("org.test.Editor")}).isEmpty());
    }

    void opaqueProcessesAreCountedButNeverTargeted()
    {
        DiscoveryFixture fixture;
        const auto group = QStringLiteral("app.slice/app-org.test.Opaque-a.scope");
        fixture.group(group, {100, 106});
        fixture.process(100, 1, fixture.uid, fixture.uid, QStringLiteral("Opaque"), fixture.groupPath(group), 100, 100);
        fixture.process(106, 100, fixture.uid, fixture.uid, QStringLiteral("private-helper"), fixture.groupPath(group), 100, 100, -1, false);
        fixture.write(fixture.procRoot() + QStringLiteral("/106/stat"), "identity inaccessible");
        ApplicationProcessModel model;
        configure(model, fixture);
        model.setIdentityHints({QVariantMap{{QStringLiteral("pid"), 100}, {QStringLiteral("startTime"), QStringLiteral("1000")}}});
        model.update();
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        QString error;
        QVERIFY2(equivalent(old, currentSnapshot(model), error), qPrintable(error));
        QCOMPARE(currentSnapshot(model).pids, QSet<qint64>({100, 106}));
        const auto targets = model.captureTargets({QStringLiteral("org.test.Opaque")});
        QCOMPARE(targets.size(), 1);
        QCOMPARE(targets.first().toMap().value(QStringLiteral("pid")).toLongLong(), 100);
        QVERIFY(!model.statusMessage().isEmpty());
        QVERIFY(QDir(fixture.groupRoot()).removeRecursively());
        fixture.makeDirectory(fixture.groupRoot());
        model.update();
        QVERIFY2(equivalent(old, currentSnapshot(model), error), qPrintable(error));
        QCOMPARE(model.captureTargets({QStringLiteral("org.test.Opaque")}).size(), 1);
        fixture.group(group, {100, 106});
        fixture.process(106, 1, fixture.uid + 1, fixture.uid + 1, QStringLiteral("recovered"), fixture.groupPath(group), 100, 100, 55555, false);
        model.update();
        QVERIFY(legacySnapshot(fixture, old));
        QVERIFY2(equivalent(old, currentSnapshot(model), error), qPrintable(error));
        QCOMPARE(model.captureTargets({QStringLiteral("org.test.Opaque")}).size(), 1);
    }

    void racedMembershipDoesNotDropOrDoubleCountHelpers()
    {
        DiscoveryFixture fixture;
        populate(fixture);
        // The procfs path was sampled before the privileged helper moved into
        // the application group; its later PID file is authoritative evidence
        // for accounting, not a reason to discard it on a UID filter.
        fixture.process(104, 1, fixture.uid + 1, fixture.uid + 1, QStringLiteral("moving-helper"), QStringLiteral("/previous-group"), 100, 100, -1, false);
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        ApplicationProcessModel model;
        configure(model, fixture);
        model.update();
        auto current = currentSnapshot(model);
        QVERIFY((old.pids - current.pids).isEmpty());
        QVERIFY(current.rows.value(QStringLiteral("org.test.Editor")).pids.contains(104));
        QVERIFY(!current.duplicatePid);
        QVERIFY(!model.statusMessage().isEmpty());
        QVERIFY(model.captureTargets({QStringLiteral("org.test.Editor")}).isEmpty());

        // A moving PID may be observed in two files. Preserve its single
        // accounting identity rather than inflating the captured process count.
        fixture.group(QStringLiteral("app.slice/app-org.test.Editor@b.service"), {102, 104});
        model.update();
        current = currentSnapshot(model);
        QVERIFY((old.pids - current.pids).isEmpty());
        QCOMPARE(current.rows.value(QStringLiteral("org.test.Editor")).pids, old.rows.value(QStringLiteral("org.test.Editor")).pids);
        QVERIFY(!current.duplicatePid);
        QVERIFY(!model.statusMessage().isEmpty());
    }

    void headlessGroupDoesNotRequireReadableExecutableOrName()
    {
        DiscoveryFixture fixture;
        QVERIFY(QDir(fixture.groupRoot()).removeRecursively());
        fixture.makeDirectory(fixture.groupRoot());
        fixture.process(300, 1, fixture.uid, fixture.uid, {}, QStringLiteral("/"), 300, 300, -1, false);
        ApplicationProcessModel model;
        configure(model, fixture);
        model.update();
        QCOMPARE(model.rowCount(), 1);
        const auto index = model.index(0, 0);
        QVERIFY(index.data(ApplicationProcessModel::ApplicationId).toString() != QLatin1String("services"));
        QCOMPARE(index.data(ProcessDataModel::PIDs).toList().size(), 1);
        QVERIFY(!index.data(ProcessDataModel::Value).toString().isEmpty());
        QVERIFY(index.data(ApplicationProcessModel::ActionPIDs).toList().isEmpty());
    }

    void ownedOpaqueProcessDoesNotNeedGroupsToBeCounted()
    {
        DiscoveryFixture fixture;
        const auto group = QStringLiteral("app.slice/app-org.test.Opaque-a.scope");
        fixture.group(group, {300});
        fixture.process(300, 1, fixture.uid, fixture.uid, {}, fixture.groupPath(group), -1, -1, -1, false);
        fixture.write(fixture.procRoot() + QStringLiteral("/300/stat"), "identity inaccessible");
        DiscoverySnapshot old;
        QVERIFY(legacySnapshot(fixture, old));
        QVERIFY(QDir(fixture.groupRoot()).removeRecursively());
        fixture.makeDirectory(fixture.groupRoot());
        QVERIFY(QFile::remove(fixture.procRoot() + QStringLiteral("/300/cgroup")));
        ApplicationProcessModel model;
        configure(model, fixture);
        model.update();
        QCOMPARE(currentSnapshot(model).pids, old.pids);
        QCOMPARE(currentSnapshot(model).pids, QSet<qint64>{300});
        QVERIFY(!model.statusMessage().isEmpty());
        QVERIFY(model.captureTargets({QStringLiteral("services")}).isEmpty());
    }

    void unreadableOwnershipRetainsKnownFamilyButNotUnrelatedProcesses()
    {
        DiscoveryFixture fixture;
        QVERIFY(QDir(fixture.groupRoot()).removeRecursively());
        fixture.makeDirectory(fixture.groupRoot());
        fixture.process(310, 1, fixture.uid, fixture.uid, QStringLiteral("GroupLeader"), QStringLiteral("/"), 310, 310);
        fixture.process(311, 310, fixture.uid + 1, fixture.uid + 1, QStringLiteral("private-helper"), QStringLiteral("/"), 310, 310, -1, false);
        fixture.process(312, 1, fixture.uid + 1, fixture.uid + 1, QStringLiteral("unrelated"), QStringLiteral("/"), 312, 312, -1, false);
        fixture.write(fixture.procRoot() + QStringLiteral("/311/status"), "ownership inaccessible");
        fixture.write(fixture.procRoot() + QStringLiteral("/312/status"), "ownership inaccessible");
        ApplicationProcessModel model;
        configure(model, fixture);
        model.update();
        const auto current = currentSnapshot(model);
        QCOMPARE(current.pids, QSet<qint64>({310, 311}));
        QCOMPARE(current.visibleRows, 1);
        QVERIFY(!current.pids.contains(312));
        QVERIFY(!model.statusMessage().isEmpty());
        QVERIFY(model.index(0, 0).data(ApplicationProcessModel::ActionPIDs).toList().isEmpty());
    }
};

QTEST_GUILESS_MAIN(ApplicationDiscoveryTest)
#include "applicationdiscoverytest.moc"
