/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include "processcore/application_controller.h"
#include "processcore/application_data_model.h"
#include "processcore/application_process_model.h"
#include "processcore/application_resolver_p.h"
#include "processcore/cgroup.h"
#include "processcore/extended_process_list.h"
#include "processcore/memoryinfo_p.h"
#include "processcore/process_attribute.h"
#include "processcore/process_data_model.h"
#include <KService>
#include <KUser>
#include <QAbstractItemModelTester>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <cmath>
#include <csignal>
#include <formatter/Formatter.h>
#include <vector>

using namespace KSysGuard;
using namespace KSysGuard::ApplicationTracking;

// Exercise the old model's data()/headerData() with deterministic membership.
// No cgroup filesystem, service manager, or live process actions are involved.
class LegacyApplicationFixture : public CGroupDataModel {
public:
    LegacyApplicationFixture(const QString &id, const QList<Process *> &members)
        : CGroupDataModel(QStringLiteral("/__applications_parity_fixture_missing__"))
        , group(id)
        , members(members)
    {
        setEnabled(false);
    }
    int rowCount(const QModelIndex &parent = {}) const override
    {
        return parent.isValid() ? 0 : 1;
    }
    QModelIndex index(int row, int column, const QModelIndex &parent = {}) const override
    {
        return !parent.isValid() && row == 0 && column >= 0 && column < columnCount() ? createIndex(row, column, const_cast<CGroup *>(&group)) : QModelIndex();
    }
    CGroup group;
    QList<Process *> members;

protected:
    QList<Process *> processesFor(CGroup *) const override
    {
        return members;
    }
};

class ApplicationProcessModelTest : public QObject {
    Q_OBJECT
    const qint64 uid = KUserId::currentEffectiveUserId().nativeId();
    ProcessInfo process(qint64 pid, qint64 parent, const QString &executable) const
    {
        return {pid, parent, pid * 10, uid, uid, executable, QStringLiteral("test"), {}};
    }
    QVariantMap hint(const ProcessInfo &p, const QString &id = {}) const
    {
        return {{QStringLiteral("pid"), p.pid}, {QStringLiteral("startTime"), QString::number(p.startTime)}, {QStringLiteral("desktopId"), id}};
    }
private Q_SLOTS:
    void initTestCase()
    {
        QCoreApplication::addLibraryPath(QStringLiteral(APPLICATION_TEST_PLUGIN_PATH));
    }

    void noSystemdAndExclusiveMembership()
    {
        DesktopIndex index;
        index.add({QStringLiteral("browser.desktop"), QStringLiteral("Browser"), {}, {}, false}, QStringLiteral("/test/browser"));
        index.add({QStringLiteral("editor.desktop"), QStringLiteral("Editor"), {}, {}, false}, QStringLiteral("/test/editor"));
        Resolver resolver;
        const auto browser = process(100, 10, QStringLiteral("/test/browser"));
        const auto helper = process(101, 100, QStringLiteral("/test/helper"));
        const auto editor = process(102, 100, QStringLiteral("/test/editor"));
        const auto daemon = process(103, 10, QStringLiteral("/test/daemon"));
        auto foreign = process(104, 100, QStringLiteral("/test/helper"));
        foreign.uid += 1;
        auto unrelated = process(105, 1, QStringLiteral("/test/foreign-daemon"));
        unrelated.uid += 1;
        auto assigned = resolver.resolve({browser, helper, editor, daemon, foreign, unrelated}, uid, {}, index);
        QCOMPARE(assigned.size(), 5);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("browser.desktop"));
        QCOMPARE(assigned.value(101).application.id, QStringLiteral("browser.desktop"));
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("editor.desktop"));
        QCOMPARE(assigned.value(103).application.id, QStringLiteral("services"));
        QCOMPARE(assigned.value(104).application.id, QStringLiteral("browser.desktop"));
        QVERIFY(!assigned.value(104).actionEligible);
        QVERIFY(!assigned.contains(105));
    }

    void terminalBoundaryAndWindowIdentity()
    {
        DesktopIndex index;
        index.add({QStringLiteral("terminal.desktop"), QStringLiteral("Terminal"), {}, {}, true, true}, {}, QStringLiteral("terminal"), false);
        index.add({QStringLiteral("gui.desktop"), QStringLiteral("GUI"), {}, {}, false}, QStringLiteral("/test/gui"));
        const auto terminal = process(100, 10, QStringLiteral("/test/terminal"));
        const auto shell = process(101, 100, QStringLiteral("/bin/bash"));
        const auto job = process(102, 101, QStringLiteral("/test/job"));
        const auto gui = process(103, 101, QStringLiteral("/test/gui"));
        Resolver resolver;
        auto assigned = resolver.resolve({terminal, shell, job, gui}, uid, {hint(terminal, QStringLiteral("terminal"))}, index);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("terminal.desktop"));
        QCOMPARE(assigned.value(101).application.id, QStringLiteral("terminal.desktop"));
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("terminal.desktop"));
        QVERIFY(!assigned.value(101).actionEligible);
        QVERIFY(!assigned.value(102).actionEligible);
        QVERIFY(assigned.value(100).actionEligible);
        QCOMPARE(assigned.value(103).application.id, QStringLiteral("gui.desktop"));
        // Minimized/closed windows do not erase a still-running identified app.
        assigned = resolver.resolve({terminal, shell, job, gui}, uid, {}, index);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("terminal.desktop"));
    }

    void reparentReuseAndExecutableChange()
    {
        DesktopIndex index;
        auto root = process(100, 10, QStringLiteral("/test/root"));
        auto child = process(101, 100, QStringLiteral("/test/helper"));
        Resolver resolver;
        auto assigned = resolver.resolve({root, child}, uid, {hint(root)}, index);
        const auto id = assigned.value(100).application.id;
        child.parentPid = 1;
        assigned = resolver.resolve({child}, uid, {}, index);
        QCOMPARE(assigned.value(101).application.id, id);
        child.startTime++;
        assigned = resolver.resolve({child}, uid, {}, index);
        QCOMPARE(assigned.value(101).application.id, QStringLiteral("services"));
        assigned = resolver.resolve({root}, uid, {hint(root)}, index);
        root.executable = QStringLiteral("/test/different");
        assigned = resolver.resolve({root}, uid, {}, index);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("services"));
    }

    void ambiguityAndStaleHints()
    {
        DesktopIndex index;
        index.add({QStringLiteral("a.desktop"), {}, {}, {}, false}, QStringLiteral("/test/shared"), QStringLiteral("Shared"));
        index.add({QStringLiteral("b.desktop"), {}, {}, {}, false}, QStringLiteral("/test/shared"), QStringLiteral("Shared"));
        QVERIFY(index.byExecutable(QStringLiteral("/test/shared")).id.isEmpty());
        QVERIFY(index.byWindowClass(QStringLiteral("Shared")).id.isEmpty());
        auto shared = process(100, 10, QStringLiteral("/test/shared"));
        Resolver resolver;
        auto stale = hint(shared, QStringLiteral("a"));
        stale.insert(QStringLiteral("startTime"), QStringLiteral("1"));
        auto assigned = resolver.resolve({shared}, uid, {stale}, index);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("services"));
        assigned = resolver.resolve({shared}, uid, {hint(shared, QStringLiteral("a")), hint(shared, QStringLiteral("b"))}, index);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("services"));
        shared.executable.clear();
        assigned = resolver.resolve({shared}, uid, {hint(shared, QStringLiteral("a"))}, index);
        QCOMPARE(assigned.value(100).application.id, QStringLiteral("services"));
    }

    void aggregation()
    {
        Process first, second;
        ProcessAttribute attribute(QStringLiteral("test"), nullptr);
        attribute.setData(&first, 2.0);
        attribute.setData(&second, 4.0);
        QCOMPARE(attribute.groupData({&first, &second}).toDouble(), 6.0);
        attribute.setGroupAggregation(ProcessAttribute::GroupAggregation::Unsupported);
        QVERIFY(!attribute.groupData({&first, &second}).isValid());
        attribute.setGroupAggregation(ProcessAttribute::GroupAggregation::Sum);
        QCOMPARE(attribute.groupData({&first, &second}).toDouble(), 6.0);
        attribute.setGroupAggregation(ProcessAttribute::GroupAggregation::Average);
        QCOMPARE(attribute.groupData({&first, &second}).toDouble(), 3.0);
        QVERIFY(std::isnan(attribute.groupData({}).toDouble()));
        attribute.setGroupAggregation(ProcessAttribute::GroupAggregation::First);
        QCOMPARE(attribute.groupData({&first, &second}).toDouble(), 2.0);
        attribute.clearData(&first);
        attribute.setGroupAggregation(ProcessAttribute::GroupAggregation::Sum);
        QCOMPARE(attribute.groupData({&first, &second}).toDouble(), 4.0);
        attribute.setGroupAggregation(ProcessAttribute::GroupAggregation::FirstValid);
        attribute.setData(&second, QStringLiteral("GPU"));
        QCOMPARE(attribute.groupData({&first, &second}).toString(), QStringLiteral("GPU"));
    }

    void stableRowsAndProtectedBackground()
    {
        ApplicationProcessModel model;
        QList<ProcessInfo> inventory;
        model.setInventorySource([&inventory] {
            return inventory;
        });
        model.setEnabledAttributes({QStringLiteral("appName"), QStringLiteral("menuId")});
        QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::QtTest);
        auto root = process(100, 10, QStringLiteral("/test/not-installed"));
        const auto background = process(101, 10, QStringLiteral("/test/daemon"));
        inventory = {root, background};
        model.setIdentityHints({hint(root)});
        model.update();
        QVERIFY(model.available());
        QCOMPARE(model.rowCount(), 2);
        const auto id = model.data(model.index(0, 0), ApplicationProcessModel::ApplicationId).toString();
        QVERIFY(id != QLatin1String("services"));
        QPersistentModelIndex persistent(model.index(0, 0));
        const auto captured = model.captureTargets({id});
        QCOMPARE(captured.size(), 1);
        connect(&model, &QAbstractItemModel::rowsRemoved, this, [&model, id] {
            QCOMPARE(model.rowForApplication(id), -1);
            QVERIFY(model.captureTargets({id}).isEmpty());
        });
        QVERIFY(model.captureTargets({id, QStringLiteral("services")}).isEmpty());
        QVERIFY(!model.data(model.index(model.rowForApplication(QStringLiteral("services")), 0), ApplicationProcessModel::ActionEligible).toBool());
        model.update();
        QVERIFY(persistent.isValid());
        QCOMPARE(persistent.data(ApplicationProcessModel::ApplicationId).toString(), id);
        inventory = {background};
        model.update();
        QVERIFY(!persistent.isValid());
        QVERIFY(!model.containsTarget(captured.first().toMap()));
        inventory.clear();
        model.update();
        QVERIFY(model.available());
        QCOMPARE(model.rowCount(), 0);
        model.setEnabled(false);
        inventory = {root};
        model.update();
        QCOMPARE(model.rowCount(), 0);
        model.setEnabled(true);
        QCOMPARE(model.rowCount(), 1);
    }

    void guardedActions()
    {
        ApplicationProcessModel model;
        auto app = process(200, 10, QStringLiteral("/test/application"));
        auto helper = process(201, 200, QStringLiteral("/test/helper"));
        QList<ProcessInfo> inventory{app, helper};
        model.setInventorySource([&inventory] {
            return inventory;
        });
        model.setEnabledAttributes({QStringLiteral("appName")});
        model.setIdentityHints({hint(app)});
        model.update();
        const auto id = model.index(0, 0).data(ApplicationProcessModel::ApplicationId).toString();
        ApplicationController controller;
        controller.setModel(&model);
        QMap<qint64, ProcessInfo> live{{app.pid, app}, {helper.pid, helper}};
        QList<qint64> dispatched;
        controller.setActionAdapters(
            [&live](qint64 pid) {
                return live.value(pid);
            },
            [&dispatched](const auto &info, int) {
                dispatched.append(info.pid);
                return QString();
            });
        auto token = controller.capture({id});
        QVERIFY(!token.isEmpty());
        // A new helper after confirmation is not silently added to the action.
        auto newHelper = process(202, 200, QStringLiteral("/test/helper"));
        inventory.append(newHelper);
        live.insert(202, newHelper);
        QVERIFY(controller.sendSignal(token, SIGTERM));
        QCOMPARE(dispatched, QList<qint64>({200, 201}));
        QVERIFY(!controller.sendSignal(token, SIGTERM)); // single use
        dispatched.clear();

        token = controller.capture({id});
        live[200].startTime++;
        live[201].euid++;
        QVERIFY(!controller.sendSignal(token, SIGKILL));
        QCOMPARE(dispatched, QList<qint64>({202}));
        QVERIFY(!controller.statusMessage().isEmpty());

        dispatched.clear();
        token = controller.capture({id});
        QVERIFY(!controller.sendSignal(token, 0));
        QVERIFY(dispatched.isEmpty());
        token = controller.capture({id});
        controller.cancel(token);
        QVERIFY(!controller.sendSignal(token, SIGTERM));

        auto background = process(300, 10, QStringLiteral("/test/background"));
        inventory.append(background);
        model.update();
        QVERIFY(controller.capture({id, QStringLiteral("services")}).isEmpty());
        QVERIFY(controller.capture({QStringLiteral("services")}).isEmpty());
        token = controller.capture({id});
        QVERIFY(!controller.applyScheduling(token, -100, 0, 0, 0, 0));

        // Simulate a kernel that cannot safely signal; no fallback operation.
        live[200] = app;
        live[201] = helper;
        controller.setActionAdapters(
            [&live](qint64 pid) {
                return live.value(pid);
            },
            [](const auto &, int) {
                return QStringLiteral("pidfds unavailable");
            });
        token = controller.capture({id});
        QVERIFY(!controller.sendSignal(token, SIGTERM));
        QVERIFY(controller.statusMessage().contains(QLatin1String("pidfds unavailable")));
        QVERIFY(dispatched.isEmpty());
    }

    void optionalScopesDoNotCreateApplicationsOrOverrideParents()
    {
        DesktopIndex index;
        index.add({QStringLiteral("org.test.Browser.desktop"), {}, {}, {}, false}, QStringLiteral("/test/browser"));
        index.add({QStringLiteral("org.test.Editor.desktop"), {}, {}, {}, false}, QStringLiteral("/test/editor"));
        auto browser = process(100, 10, QStringLiteral("/test/browser"));
        auto editor = process(101, 10, QStringLiteral("/test/editor"));
        auto helper = process(102, 1, QStringLiteral("/test/helper"));
        helper.cgroup = QStringLiteral("/arbitrary/layout/flatpak-org.test.Browser-instance.scope");
        Resolver resolver;
        auto assigned = resolver.resolve({helper}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("services"));
        assigned = resolver.resolve({browser, helper}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("org.test.Browser.desktop"));
        helper.parentPid = editor.pid;
        assigned = resolver.resolve({browser, editor, helper}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("org.test.Editor.desktop"));
        helper.parentPid = 1;
        helper.startTime++;
        helper.cgroup = QStringLiteral("/user.slice/background.slice/session.scope");
        assigned = resolver.resolve({browser, helper}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("services"));
        helper.cgroup = QStringLiteral("/app-org.test.Browser\\xZZ-instance.scope");
        assigned = resolver.resolve({browser, helper}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("services"));
    }

    void changedAncestryAndCredentials()
    {
        DesktopIndex index;
        index.add({QStringLiteral("one.desktop"), {}, {}, {}, false}, QStringLiteral("/test/one"));
        index.add({QStringLiteral("two.desktop"), {}, {}, {}, false}, QStringLiteral("/test/two"));
        auto one = process(100, 1, QStringLiteral("/test/one"));
        auto two = process(101, 1, QStringLiteral("/test/two"));
        auto child = process(102, 100, QStringLiteral("/test/child"));
        Resolver resolver;
        auto assigned = resolver.resolve({one, two, child}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("one.desktop"));
        child.parentPid = 101;
        assigned = resolver.resolve({one, two, child}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("two.desktop"));
        child.euid++;
        assigned = resolver.resolve({one, two, child}, uid, {}, index);
        QCOMPARE(assigned.value(102).application.id, QStringLiteral("two.desktop"));
        QVERIFY(!assigned.value(102).actionEligible);

        auto broker = process(500, 1, {});
        broker.uid = broker.euid = uid + 1;
        one.uid = one.euid = uid + 1;
        one.parentPid = broker.pid;
        one.executable.clear();
        for (int refresh = 0; refresh < 2; ++refresh) {
            assigned = resolver.resolve({one, two, child, broker}, uid, {}, index);
            QCOMPARE(assigned.value(100).application.id, QStringLiteral("one.desktop"));
            QVERIFY(!assigned.value(100).actionEligible);
            QVERIFY(!assigned.contains(500));
        }
    }

    void boundedProcfsReader()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QVERIFY(QDir(directory.path()).mkpath(QStringLiteral("100")));
        QList<QByteArray> fields;
        for (int i = 0; i < 20; ++i) {
            fields.append("0");
        }
        fields[0] = "S";
        fields[1] = "42";
        fields[19] = "12345";
        const auto write = [&](const QString &name, const QByteArray &bytes) {
            QFile file(directory.filePath(QStringLiteral("100/") + name));
            return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size();
        };
        QVERIFY(write(QStringLiteral("stat"), "100 (name with ) parens) " + fields.join(' ') + '\n'));
        QVERIFY(write(QStringLiteral("status"), "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n"));
        auto info = readProcess(100, directory.path());
        QCOMPARE(info.pid, 100);
        QCOMPARE(info.parentPid, 42);
        QCOMPARE(info.startTime, 12345);
        QCOMPARE(info.name, QStringLiteral("name with ) parens"));
        QVERIFY(info.executable.isEmpty()); // Unreadable exe is normal, not PID 0.
        QVERIFY(write(QStringLiteral("status"), "Uid:\tinvalid\t1000\n"));
        QCOMPARE(readProcess(100, directory.path()).pid, -1);
        QVERIFY(write(QStringLiteral("stat"), "truncated"));
        QCOMPARE(readProcess(100, directory.path()).pid, -1);
        QCOMPARE(readProcess(999, directory.path()).pid, -1);
        QCOMPARE(readProcess(0, directory.path()).pid, -1);
    }

    void longAncestryAndCycles()
    {
        DesktopIndex index;
        index.add({QStringLiteral("root.desktop"), {}, {}, {}, false}, QStringLiteral("/test/root"));
        QList<ProcessInfo> inventory{process(100000, 1, QStringLiteral("/test/root"))};
        // Children sort before their parents, exercising memoized traversal.
        for (qint64 pid = 10000; pid < 20000; ++pid) {
            inventory.append(process(pid, pid == 19999 ? 100000 : pid + 1, QStringLiteral("/test/helper")));
        }
        Resolver resolver;
        QElapsedTimer timer;
        timer.start();
        const auto assigned = resolver.resolve(inventory, uid, {}, index);
        QCOMPARE(assigned.size(), inventory.size());
        QCOMPARE(assigned.value(10000).application.id, QStringLiteral("root.desktop"));
        QVERIFY2(timer.elapsed() < 10000, "Application grouping unexpectedly slow for 10,000 processes");
        const auto cyclic = resolver.resolve({process(10, 11, QStringLiteral("/test/a")), process(11, 10, QStringLiteral("/test/b"))}, uid, {}, index);
        QCOMPARE(cyclic.size(), 2);
        QCOMPARE(cyclic.value(10).application.id, QStringLiteral("services"));
    }

    void everySignalAndSchedulingSafeguards()
    {
        ApplicationProcessModel model;
        auto app = process(200, 1, QStringLiteral("/test/app"));
        QList<ProcessInfo> inventory{app};
        model.setInventorySource([&inventory] {
            return inventory;
        });
        model.setEnabledAttributes({QStringLiteral("appName")});
        model.setIdentityHints({hint(app)});
        model.update();
        const auto id = model.index(0, 0).data(ApplicationProcessModel::ApplicationId).toString();
        ApplicationController controller;
        controller.setModel(&model);
        QList<int> receivedSignals;
        controller.setActionAdapters(
            [&app](qint64) {
                return app;
            },
            [&receivedSignals](const auto &, int signal) {
                receivedSignals.append(signal);
                return QString();
            });
        const QList<int> supported{SIGTERM, SIGKILL, SIGSTOP, SIGCONT, SIGHUP, SIGINT, SIGUSR1, SIGUSR2};
        for (int signal : supported) {
            QVERIFY(controller.sendSignal(controller.capture({id, id}), signal));
        }
        QCOMPARE(receivedSignals, supported); // Duplicate selected IDs are not dispatched twice.
        QList<int> operations;
        bool normalized = false;
        controller.setSchedulingAdapter([&operations, &normalized](const auto &, int operation, int, int priority) {
            operations.append(operation);
            if (operation == 1) {
                normalized = priority == 0;
            }
            return QString();
        });
        QVERIFY(controller.applyScheduling(controller.capture({id}), 10, Process::Other, 12, 0, 0));
        QCOMPARE(operations, QList<int>({0, 1, 2}));
        QVERIFY(normalized);
        operations.clear();
        controller.setSchedulingAdapter([&operations](const auto &, int operation, int, int) {
            operations.append(operation);
            return QStringLiteral("permission denied");
        });
        QVERIFY(!controller.applyScheduling(controller.capture({id}), -10, Process::Other, 0, 0, 0));
        QCOMPARE(operations, QList<int>({0})); // No privileged retry, no later operations.
        operations.clear();
        controller.setSchedulingAdapter([&operations, &app](const auto &, int operation, int, int) {
            operations.append(operation);
            app.startTime++;
            return QString();
        });
        QVERIFY(!controller.applyScheduling(controller.capture({id}), 10, Process::Other, 0, 0, 0));
        QCOMPARE(operations, QList<int>({0})); // Revalidate between scheduling calls.
        const auto pending = controller.capture({id});
        model.setEnabled(false);
        QVERIFY(!controller.sendSignal(pending, SIGTERM));
        QVERIFY(controller.capture({id}).isEmpty());
    }

    void sensorSubscriptionsPause()
    {
        ApplicationProcessModel model;
        const auto processes = ExtendedProcesses::instance();
        ProcessAttribute *usage = nullptr;
        for (auto *attribute : processes->attributes()) {
            if (attribute->id() == QLatin1String("usage")) {
                usage = attribute;
            }
        }
        QVERIFY(usage);
        model.setEnabledAttributes({QStringLiteral("usage")});
        QVERIFY(usage->enabled());
        model.setEnabled(false);
        QVERIFY(!usage->enabled());
        model.setEnabled(true);
        QVERIFY(usage->enabled());
    }

    void signalOnlyDisposableChild()
    {
#ifdef Q_OS_LINUX
        QProcess child;
        child.start(QStringLiteral("/bin/sleep"), {QStringLiteral("60")});
        QVERIFY(child.waitForStarted());
        const auto info = readProcess(child.processId());
        QVERIFY(info.pid > 1);
        ApplicationProcessModel model;
        model.setInventorySource([info] {
            return QList<ProcessInfo>{info};
        });
        model.setEnabledAttributes({QStringLiteral("appName")});
        model.setIdentityHints({hint(info)});
        model.update();
        const auto id = model.index(0, 0).data(ApplicationProcessModel::ApplicationId).toString();
        ApplicationController controller;
        controller.setModel(&model);
        const auto result = controller.sendSignal(controller.capture({id}), SIGTERM);
        if (!result && controller.statusMessage().contains(QLatin1String("unavailable"))) {
            child.kill();
            child.waitForFinished();
            QSKIP("Kernel does not provide safe pidfd signaling");
        }
        QVERIFY2(result, qPrintable(controller.statusMessage()));
        QVERIFY(child.waitForFinished(5000));
#else
        QSKIP("Linux pidfd integration test");
#endif
    }

    void liveIdentityMatchesSharedInventory()
    {
#ifdef Q_OS_LINUX
        ApplicationProcessModel model;
        model.setEnabledAttributes({QStringLiteral("appName"), QStringLiteral("usage")});
        const auto identity = model.processIdentity(QCoreApplication::applicationPid());
        QVERIFY(!identity.isEmpty());
        model.setIdentityHints({identity});
        model.update();
        QVERIFY(model.available());
        QString id;
        for (int row = 0; row < model.rowCount(); ++row) {
            const auto index = model.index(row, 0);
            const auto pids = index.data(ProcessDataModel::PIDs).toList();
            if (pids.contains(QVariant(QCoreApplication::applicationPid()))) {
                id = index.data(ApplicationProcessModel::ApplicationId).toString();
                QVERIFY(index.data(ApplicationProcessModel::ActionEligible).toBool());
                break;
            }
        }
        if (id.isEmpty()) {
            // A test launched over SSH/CI can be outside an existing desktop
            // user-service scope. Matching the legacy scope intentionally does
            // not add this otherwise readable current-user process to the view.
            const auto self = readProcess(QCoreApplication::applicationPid());
            const auto scope = discoverGroups(CGroup::cgroupSysBasePath(), uid, {self});
            QVERIFY(scope.available && scope.complete);
            QVERIFY(!scope.bindings.contains(self.pid));
            return;
        }
        const auto targets = model.captureTargets({id});
        bool found = false;
        for (const auto &value : targets) {
            const auto target = value.toMap();
            if (target.value(QStringLiteral("pid")) == identity.value(QStringLiteral("pid"))) {
                QCOMPARE(target.value(QStringLiteral("startTime")), identity.value(QStringLiteral("startTime")));
                QVERIFY(model.containsTarget(target));
                found = true;
            }
        }
        QVERIFY(found);
#else
        QSKIP("Linux procfs identity integration test");
#endif
    }

    void allLegacyColumnsAndValuesArePreserved()
    {
        Process first(100, 1, nullptr), second(101, 100, &first);
        const auto root = process(100, 1, QStringLiteral("/test/parity-app"));
        const auto child = process(101, 100, QStringLiteral("/test/parity-helper"));
        first.setStartTime(root.startTime);
        second.setStartTime(child.startTime);
        for (auto *p : {&first, &second}) {
            p->setUid(uid);
            p->setEuid(uid);
            p->setName(QStringLiteral("parity-process"));
            p->setCommand(QStringLiteral("parity-command --example"));
            p->setStatus(Process::Running);
        }
        first.setUserUsage(12);
        second.setUserUsage(4);
        first.setSysUsage(3);
        second.setSysUsage(1);
        first.setTotalUserUsage(16);
        second.setTotalUserUsage(4);
        first.setTotalSysUsage(4);
        second.setTotalSysUsage(1);
        first.setNiceLevel(-5);
        second.setNiceLevel(2);
        first.setIoCharactersActuallyReadRate(4096);
        second.setIoCharactersActuallyReadRate(8192);
        first.setIoCharactersActuallyWrittenRate(1024);
        second.setIoCharactersActuallyWrittenRate(2048);
        int memory = 100;
        for (auto *p : {&first, &second}) {
            auto *info = p->memoryInfo();
            info->precise.lastUpdate = std::chrono::steady_clock::now();
            info->precise.rss = memory * 2;
            info->precise.pss = memory;
            info->precise.priv = memory / 2;
            info->precise.swap = memory / 10;
            info->vmSize = memory * 10;
            memory += 100;
        }

        ApplicationProcessModel model;
        model.setInventorySource([root, child] {
            return QList<ProcessInfo>{root, child};
        });
        model.setProcessLookup([&](qint64 pid) {
            return pid == 100 ? &first : pid == 101 ? &second : nullptr;
        });
        model.setIdentityHints({hint(root)});
        LegacyApplicationFixture legacy(QStringLiteral("app-org.test.Parity-example.scope"), {&first, &second});
        const auto providers = ExtendedProcesses::instance()->extendedAttributes();
        for (auto *attribute : providers) {
            if (attribute->id() == QLatin1String("gpu_module")) {
                attribute->setData(&first, QString());
                attribute->setData(&second, QStringLiteral("amdgpu"));
            } else {
                attribute->setData(&first, 40.0);
                attribute->setData(&second, 60.0);
            }
        }
        auto oldAttributes = legacy.availableAttributes();
        auto newAttributes = model.availableAttributes();
        oldAttributes.sort();
        newAttributes.sort();
        QCOMPARE(newAttributes, oldAttributes);
        for (const auto &id : {QStringLiteral("totalUserUsage"), QStringLiteral("totalSysUsage"), QStringLiteral("totalUsage")}) {
            QVERIFY(newAttributes.contains(id));
        }
        legacy.setEnabledAttributes(oldAttributes);
        model.setEnabledAttributes(newAttributes);
        model.update();
        QCOMPARE(model.rowCount(), 1);
        QCOMPARE(model.columnCount(), legacy.columnCount());
        const QList<int> headerRoles{Qt::DisplayRole,
                                     ProcessDataModel::Name,
                                     ProcessDataModel::ShortName,
                                     ProcessDataModel::Attribute,
                                     ProcessDataModel::Unit,
                                     ProcessDataModel::Minimum,
                                     ProcessDataModel::Maximum};
        for (int column = 0; column < oldAttributes.size(); ++column) {
            const auto id = oldAttributes.at(column);
            for (int role : headerRoles) {
                QCOMPARE(model.headerData(column, Qt::Horizontal, role), legacy.headerData(column, Qt::Horizontal, role));
            }
            if (id == QLatin1String("appName") || id == QLatin1String("iconName") || id == QLatin1String("menuId")) {
                continue; // Identity metadata is compared with a real desktop entry below.
            }
            const auto current = model.index(0, column);
            const auto reference = legacy.index(0, column);
            const auto expected = legacy.data(reference, ProcessDataModel::Value);
            const auto actual = model.data(current, ProcessDataModel::Value);
            QVERIFY2(actual == expected, qPrintable(QStringLiteral("Value mismatch for %1: old=%2 new=%3").arg(id, expected.toString(), actual.toString())));
            QCOMPARE(model.data(current, Qt::DisplayRole), legacy.data(reference, Qt::DisplayRole));
            QCOMPARE(model.data(current, ProcessDataModel::FormattedValue), legacy.data(reference, ProcessDataModel::FormattedValue));
            QCOMPARE(model.data(current, ProcessDataModel::PIDs), legacy.data(reference, ProcessDataModel::PIDs));
        }
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("usage"))).data(ProcessDataModel::Value).toDouble(), 20.0);
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("totalUserUsage"))).data(ProcessDataModel::Value).toDouble(), 10.0);
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("totalSysUsage"))).data(ProcessDataModel::Value).toDouble(), 2.5);
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("totalUsage"))).data(ProcessDataModel::Value).toDouble(), 12.5);
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("niceLevel"))).data(ProcessDataModel::Value).toDouble(), -3.0);
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("memory"))).data(ProcessDataModel::Value).toDouble(), 300.0);
        QCOMPARE(model.index(0, newAttributes.indexOf(QStringLiteral("ioCharactersActuallyReadRate"))).data(ProcessDataModel::Value).toDouble(), 12288.0);
        for (auto *attribute : providers) {
            if (attribute->id() == QLatin1String("gpu_module")) {
                QCOMPARE(model.index(0, newAttributes.indexOf(attribute->id())).data(ProcessDataModel::Value).toString(), QStringLiteral("amdgpu"));
            }
            attribute->clearData(&first);
            attribute->clearData(&second);
        }
    }

    void customAggregationAndLegacyDefaults()
    {
        Process first, second;
        CGroup reference(QStringLiteral("app-org.test.Custom-test.scope"));
        ProcessAttribute numeric(QStringLiteral("unmodified-numeric-provider"), nullptr);
        numeric.setData(&first, -3.0);
        numeric.setData(&second, 10.0);
        QCOMPARE(numeric.groupData({&first, &second}), numeric.cgroupData(&reference, {&first, &second}));
        QCOMPARE(numeric.groupData({&first, &second}).toDouble(), 7.0);
        numeric.clearData(&first);
        QCOMPARE(numeric.groupData({&first, &second}), numeric.cgroupData(&reference, {&first, &second}));

        ProcessAttribute custom(QStringLiteral("custom-summary"), nullptr);
        custom.setData(&first, QStringLiteral("device-a"));
        custom.setData(&second, QStringLiteral("device-b"));
        custom.setGroupDataFunction([&custom](const QList<Process *> &processes) {
            QStringList values;
            for (auto *process : processes) {
                values.append(custom.data(process).toString());
            }
            return values.join(QLatin1Char(','));
        });
        QCOMPARE(custom.groupData({&first, &second}).toString(), QStringLiteral("device-a,device-b"));
        QCOMPARE(custom.groupData({&first, &second}), custom.cgroupData(&reference, {&first, &second}));
        QCOMPARE(custom.groupData({}), custom.cgroupData(&reference, {}));
    }

    void desktopIdentityInformationParity()
    {
        for (const auto &service : KService::allServices()) {
            if (!service->isApplication() || service->menuId().isEmpty()) {
                continue;
            }
            auto desktopId = service->menuId();
            if (!desktopId.endsWith(QLatin1String(".desktop"))) {
                continue;
            }
            desktopId.chop(8);
            desktopId.replace(QLatin1Char('-'), QStringLiteral("\\x2d"));
            LegacyApplicationFixture legacy(QStringLiteral("app-%1-parity.scope").arg(desktopId), {});
            if (legacy.group.service()->menuId() != service->menuId()) {
                continue;
            }
            const auto root = process(100, 1, QStringLiteral("/test/metadata-app"));
            ApplicationProcessModel model;
            model.setInventorySource([root] {
                return QList<ProcessInfo>{root};
            });
            model.setIdentityHints({hint(root, service->storageId())});
            const QStringList metadata{QStringLiteral("appName"), QStringLiteral("iconName"), QStringLiteral("menuId")};
            model.setEnabledAttributes(metadata);
            legacy.setEnabledAttributes(metadata);
            model.update();
            QCOMPARE(model.rowCount(), 1);
            for (int column = 0; column < metadata.size(); ++column) {
                QCOMPARE(model.index(0, column).data(ProcessDataModel::Value), legacy.index(0, column).data(ProcessDataModel::Value));
                QCOMPARE(model.index(0, column).data(Qt::DisplayRole), legacy.index(0, column).data(Qt::DisplayRole));
            }
            return;
        }
        QSKIP("No desktop entries are installed for the desktop identity comparison");
    }

    void terminalAccountingParityAndSeparateActionTargets()
    {
        const auto terminal = process(100, 1, QStringLiteral("/test/konsole"));
        const auto shell = process(101, 100, QStringLiteral("/bin/bash"));
        auto job = process(102, 101, QStringLiteral("/test/cli-job"));
        const auto gui = process(103, 101, QStringLiteral("/test/independent-gui"));
        const auto guiHelper = process(104, 103, QStringLiteral("/test/gui-helper"));
        const auto daemon = process(105, 1, QStringLiteral("/test/daemon"));
        auto elevatedJob = process(106, 101, {});
        elevatedJob.uid = elevatedJob.euid = uid + 1;
        auto otherUserDaemon = process(107, 1, {});
        otherUserDaemon.uid = otherUserDaemon.euid = uid + 1;
        QList<ProcessInfo> inventory{terminal, shell, job, gui, guiHelper, daemon, elevatedJob, otherUserDaemon};
        QMap<qint64, Process *> lookup;
        std::vector<std::unique_ptr<Process>> samples;
        int usage = 1;
        for (const auto &info : inventory) {
            auto sample = std::make_unique<Process>(info.pid, info.parentPid, nullptr);
            sample->setStartTime(info.startTime);
            sample->setUid(info.uid);
            sample->setEuid(info.euid);
            sample->setUserUsage(usage++);
            sample->setSysUsage(0);
            sample->setIoCharactersActuallyReadRate(info.pid * 10);
            sample->setIoCharactersActuallyWrittenRate(info.pid * 4);
            sample->memoryInfo()->precise.lastUpdate = std::chrono::steady_clock::now();
            sample->memoryInfo()->precise.pss = info.pid;
            lookup.insert(info.pid, sample.get());
            samples.push_back(std::move(sample));
        }
        ApplicationProcessModel model;
        model.setInventorySource([&inventory] {
            return inventory;
        });
        model.setProcessLookup([&lookup](qint64 pid) {
            return lookup.value(pid);
        });
        model.setIdentityHints({hint(terminal), hint(gui)});
        QStringList columns{QStringLiteral("appName"), QStringLiteral("usage"), QStringLiteral("memory")};
        for (const auto &id : {QStringLiteral("netInbound"),
                               QStringLiteral("netOutbound"),
                               QStringLiteral("ioCharactersActuallyReadRate"),
                               QStringLiteral("ioCharactersActuallyWrittenRate")}) {
            if (model.availableAttributes().contains(id)) {
                columns.append(id);
            }
        }
        const auto providers = ExtendedProcesses::instance()->extendedAttributes();
        for (auto *attribute : providers) {
            for (const auto &sample : samples) {
                attribute->setData(sample.get(),
                                   attribute->id() == QLatin1String("gpu_module") ? QVariant(QStringLiteral("amdgpu")) : QVariant(double(sample->pid())));
            }
        }
        model.setEnabledAttributes(columns);
        model.update();
        QCOMPARE(model.rowCount(), 3);
        QString terminalId;
        QSet<qint64> accounted;
        QList<double> totals(columns.size(), 0.0);
        for (int row = 0; row < model.rowCount(); ++row) {
            const auto index = model.index(row, 0);
            for (const auto &value : index.data(ProcessDataModel::PIDs).toList()) {
                QVERIFY(!accounted.contains(value.toLongLong()));
                accounted.insert(value.toLongLong());
                if (value.toLongLong() == terminal.pid) {
                    terminalId = index.data(ApplicationProcessModel::ApplicationId).toString();
                }
            }
            for (int column = 1; column < columns.size(); ++column) {
                totals[column] += model.index(row, column).data(ProcessDataModel::Value).toDouble();
            }
        }
        QCOMPARE(accounted.size(), inventory.size() - 1);
        QVERIFY(!accounted.contains(otherUserDaemon.pid));
        QCOMPARE(totals.at(1), 28.0);
        QList<Process *> expectedMembers;
        for (const auto pid : accounted) {
            expectedMembers.append(lookup.value(pid));
        }
        LegacyApplicationFixture totalReference(QStringLiteral("app-org.test.Accounting-test.scope"), expectedMembers);
        totalReference.setEnabledAttributes(columns);
        for (int column = 1; column < columns.size(); ++column) {
            QCOMPARE(totals.at(column), totalReference.index(0, column).data(ProcessDataModel::Value).toDouble());
        }
        QVERIFY(!terminalId.isEmpty());
        const auto terminalRow = model.rowForApplication(terminalId);
        QCOMPARE(model.index(terminalRow, 0).data(ProcessDataModel::PIDs).toList(), QVariantList({qint64(100), qint64(101), qint64(102), qint64(106)}));
        QCOMPARE(model.index(terminalRow, 0).data(ApplicationProcessModel::ActionPIDs).toList(), QVariantList({qint64(100)}));
        LegacyApplicationFixture legacy(QStringLiteral("app-org.test.Terminal-test.scope"),
                                        {lookup.value(100), lookup.value(101), lookup.value(102), lookup.value(106)});
        legacy.setEnabledAttributes(model.enabledAttributes());
        for (int column = 1; column < columns.size(); ++column) {
            QCOMPARE(model.index(terminalRow, column).data(ProcessDataModel::Value), legacy.index(0, column).data(ProcessDataModel::Value));
            QCOMPARE(model.index(terminalRow, column).data(Qt::DisplayRole), legacy.index(0, column).data(Qt::DisplayRole));
        }
        const auto targets = model.captureTargets({terminalId});
        QCOMPARE(targets.size(), 1);
        QCOMPARE(targets.first().toMap().value(QStringLiteral("pid")).toLongLong(), terminal.pid);
        ApplicationController controller;
        controller.setModel(&model);
        QList<qint64> dispatched;
        controller.setActionAdapters(
            [&inventory](qint64 pid) {
                for (const auto &info : inventory) {
                    if (info.pid == pid) {
                        return info;
                    }
                }
                return ProcessInfo{};
            },
            [&dispatched](const ProcessInfo &info, int) {
                dispatched.append(info.pid);
                return QString();
            });
        QVERIFY(controller.sendSignal(controller.capture({terminalId}), SIGTERM));
        QCOMPARE(dispatched, QList<qint64>{terminal.pid});

        // Elevated/uncertain descendants still contribute to accounting but are
        // not direct action targets and do not disable the safe terminal target.
        inventory[2].euid++;
        lookup.value(102)->setEuid(inventory[2].euid);
        model.update();
        QCOMPARE(model.captureTargets({terminalId}).size(), 1);
        QCOMPARE(model.index(model.rowForApplication(terminalId), 1).data(ProcessDataModel::Value).toDouble(), 13.0);
        inventory = {inventory.at(1), inventory.at(2), inventory.at(6)};
        inventory[0].parentPid = 1;
        model.update();
        QCOMPARE(model.index(model.rowForApplication(terminalId), 0).data(ProcessDataModel::PIDs).toList().size(), 3);
        QVERIFY(model.captureTargets({terminalId}).isEmpty());
        for (auto *attribute : providers) {
            for (const auto &sample : samples) {
                attribute->clearData(sample.get());
            }
        }
    }
};

QTEST_GUILESS_MAIN(ApplicationProcessModelTest)
#include "applicationprocesstest.moc"
