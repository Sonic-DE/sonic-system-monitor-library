/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include "application_controller.h"
#include "application_resolver_p.h"
#include "processes_local_p.h"

#include <KLocalizedString>
#include <KUser>
#include <QElapsedTimer>
#include <QPointer>
#include <QUuid>
#include <cerrno>
#include <csignal>
#include <cstring>
#ifdef Q_OS_LINUX
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

using namespace KSysGuard;
using namespace KSysGuard::ApplicationTracking;

namespace {
bool sameTarget(const ProcessInfo &process, const QVariantMap &target, qint64 uid)
{
    return process.pid > 1 && process.pid == target.value(QStringLiteral("pid")).toLongLong() && process.startTime > 0
        && process.startTime == target.value(QStringLiteral("startTime")).toLongLong() && process.uid == uid && process.euid == uid
        && !process.executable.isEmpty() && process.executable == target.value(QStringLiteral("executable")).toString();
}

QString signalProcess(const ProcessInfo &expected, int signal)
{
#if defined(Q_OS_LINUX) && defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    const int fd = syscall(SYS_pidfd_open, expected.pid, 0);
    if (fd < 0) {
        return errno == ENOSYS ? i18n("Safe process signaling is unavailable on this kernel.") : QString::fromLocal8Bit(strerror(errno));
    }
    const auto current = readProcess(expected.pid);
    // Validate after acquiring the pidfd. Even if the numeric PID subsequently
    // disappears/recycles, the signal cannot be redirected to its replacement.
    const bool matches = current.pid == expected.pid && current.startTime == expected.startTime && current.uid == expected.uid && current.euid == expected.euid
        && current.executable == expected.executable;
    const int result = matches ? syscall(SYS_pidfd_send_signal, fd, signal, nullptr, 0) : -1;
    const int error = errno;
    close(fd);
    if (!matches) {
        return i18n("The process identity changed before the operation.");
    }
    return result == 0 ? QString() : QString::fromLocal8Bit(strerror(error));
#else
    Q_UNUSED(expected)
    Q_UNUSED(signal)
    return i18n("Safe process signaling is unavailable on this platform.");
#endif
}
}

class ApplicationController::Private {
public:
    struct Capture {
        QVariantList targets;
        qint64 created;
    };
    QPointer<ApplicationProcessModel> model;
    QHash<QString, Capture> captures;
    QElapsedTimer clock;
    qint64 uid = KUserId::currentEffectiveUserId().nativeId();
    QString status;
    std::function<ProcessInfo(qint64)> reader = [](qint64 pid) {
        return readProcess(pid);
    };
    std::function<QString(const ProcessInfo &, int)> signal = signalProcess;
    std::function<QString(const ProcessInfo &, int, int, int)> schedule;
    ProcessesLocal local;

    bool valid(const QString &token) const
    {
        const auto it = captures.constFind(token);
        return model && model->enabled() && model->available() && it != captures.cend() && clock.elapsed() - it->created < 10 * 60 * 1000;
    }
};

ApplicationController::ApplicationController(QObject *parent)
    : QObject(parent)
    , d(std::make_unique<Private>())
{
    d->clock.start();
    d->schedule = [this](const ProcessInfo &process, int operation, int mode, int priority) {
        Processes::Error result = Processes::NotSupported;
        switch (operation) {
        case 0:
            result = d->local.setNiceness(process.pid, priority);
            break;
        case 1:
            result = d->local.setScheduler(process.pid, mode, priority);
            break;
        case 2:
            if (d->local.supportsIoNiceness()) {
                result = d->local.setIoNiceness(process.pid, mode, priority);
            }
            break;
        }
        return result == Processes::NoError ? QString() : i18n("The scheduling operation failed without elevated privileges (error %1).", int(result));
    };
}
ApplicationController::~ApplicationController() = default;
ApplicationProcessModel *ApplicationController::model() const
{
    return d->model;
}
void ApplicationController::setModel(ApplicationProcessModel *model)
{
    if (d->model == model) {
        return;
    }
    d->captures.clear();
    d->model = model;
    Q_EMIT modelChanged();
}
QString ApplicationController::statusMessage() const
{
    return d->status;
}
void ApplicationController::setStatus(const QString &status)
{
    if (d->status != status) {
        d->status = status;
        Q_EMIT statusMessageChanged();
    }
}

QString ApplicationController::capture(const QStringList &ids)
{
    if (!d->model || !d->model->enabled()) {
        setStatus(i18n("The application model is unavailable."));
        return {};
    }
    d->model->update();
    const auto targets = d->model->captureTargets(ids);
    if (targets.isEmpty()) {
        setStatus(i18n("This selection contains background services, unavailable applications, or processes that cannot safely be controlled."));
        return {};
    }
    // Limit retained confirmations and discard expired requests.
    for (auto it = d->captures.begin(); it != d->captures.end();) {
        if (d->clock.elapsed() - it->created >= 10 * 60 * 1000) {
            it = d->captures.erase(it);
        } else {
            ++it;
        }
    }
    if (d->captures.size() >= 32) {
        setStatus(i18n("Too many pending application operations. Close an existing confirmation first."));
        return {};
    }
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    d->captures.insert(token, {targets, d->clock.elapsed()});
    setStatus({});
    return token;
}

void ApplicationController::cancel(const QString &capture)
{
    d->captures.remove(capture);
}

bool ApplicationController::dispatch(const QString &token, const std::function<QString(const ProcessInfo &)> &action)
{
    if (!d->valid(token)) {
        cancel(token);
        setStatus(i18n("The application operation expired or is no longer available."));
        return false;
    }
    const auto targets = d->captures.take(token).targets;
    d->model->update();
    int skipped = 0;
    int failed = 0;
    QString error;
    for (const auto &entry : targets) {
        const auto target = entry.toMap();
        const auto current = d->reader(target.value(QStringLiteral("pid")).toLongLong());
        if (!d->model->containsTarget(target) || !sameTarget(current, target, d->uid)) {
            ++skipped;
            continue;
        }
        const auto result = action(current);
        if (!result.isEmpty()) {
            ++failed;
            error = result;
        }
    }
    if (skipped || failed) {
        setStatus(i18n("Skipped %1 changed or exited processes; %2 operations failed. %3", skipped, failed, error));
        return false;
    }
    setStatus({});
    return true;
}

bool ApplicationController::sendSignal(const QString &token, int signal)
{
    // Only expose the explicit UI signal set, never process-group or arbitrary
    // numeric-PID operations. Invalid requests consume their capture too.
    const QList<int> allowed = {SIGTERM, SIGKILL, SIGSTOP, SIGCONT, SIGHUP, SIGINT, SIGUSR1, SIGUSR2};
    if (!allowed.contains(signal)) {
        cancel(token);
        setStatus(i18n("Unsupported application signal."));
        return false;
    }
    return dispatch(token, [this, signal](const ProcessInfo &process) {
        return d->signal(process, signal);
    });
}

QVariantMap ApplicationController::scheduling(const QString &token)
{
    if (!d->valid(token)) {
        return {};
    }
    QVariantMap result;
    const auto targets = d->captures.value(token).targets;
    for (const auto &entry : targets) {
        const auto target = entry.toMap();
        const auto process = d->reader(target.value(QStringLiteral("pid")).toLongLong());
        if (!d->model->containsTarget(target) || !sameTarget(process, target, d->uid)) {
            return {};
        }
        QVariantMap values = {{QStringLiteral("priority"), d->local.getNiceness(process.pid)},
                              {QStringLiteral("cpuMode"), d->local.getSchedulerClass(process.pid)},
                              {QStringLiteral("ioPriority"), d->local.getIoNiceness(process.pid)},
                              {QStringLiteral("ioMode"), d->local.getIoPriorityClass(process.pid)}};
#ifdef Q_OS_LINUX
        sched_param parameters{};
        if (sched_getparam(process.pid, &parameters) == 0) {
            values.insert(QStringLiteral("realtimePriority"), parameters.sched_priority);
        }
#endif
        if (result.isEmpty()) {
            result = values;
        } else {
            for (auto it = result.begin(); it != result.end(); ++it) {
                if (it.value() != values.value(it.key())) {
                    it.value() = QVariant();
                }
            }
        }
    }
    return result;
}

bool ApplicationController::applyScheduling(const QString &token, int niceValue, int cpuScheduler, int cpuPriority, int ioScheduler, int ioPriority)
{
    const QList<int> schedulers = {Process::Other, Process::Fifo, Process::RoundRobin, Process::Batch, Process::SchedulerIdle};
    if (niceValue < -20 || niceValue > 19 || !schedulers.contains(cpuScheduler) || cpuPriority < 0 || cpuPriority > 99 || ioScheduler < 0 || ioScheduler > 3
        || ioPriority < 0 || ioPriority > 7) {
        cancel(token);
        setStatus(i18n("Invalid scheduling parameters."));
        return false;
    }
    if (cpuScheduler != Process::Fifo && cpuScheduler != Process::RoundRobin) {
        cpuPriority = 0;
    }
    if (ioScheduler == 3) {
        ioPriority = 0;
    }
    return dispatch(token, [=, this](const ProcessInfo &process) {
        // Scheduling syscalls address numeric PIDs. Revalidate immediately
        // before *each* operation; unlike pidfd signals this is not atomic with
        // process exit. No privilege escalation is ever attempted.
        const auto validate = [&] {
            const auto current = d->reader(process.pid);
            return current.pid == process.pid && current.startTime == process.startTime && current.uid == d->uid && current.euid == d->uid
                && current.executable == process.executable;
        };
        const QList<QPair<int, int>> options = {{0, niceValue}, {cpuScheduler, cpuPriority}, {ioScheduler, ioPriority}};
        for (int operation = 0; operation < options.size(); ++operation) {
            if (operation == 0 && (cpuScheduler == Process::Fifo || cpuScheduler == Process::RoundRobin)) {
                continue; // Realtime priority is not a Unix niceness value.
            }
            if (!validate()) {
                return i18n("The process identity changed before the scheduling operation.");
            }
            const auto error = d->schedule(process, operation, options.at(operation).first, options.at(operation).second);
            if (!error.isEmpty()) {
                return error;
            }
        }
        return QString();
    });
}

void ApplicationController::setActionAdapters(std::function<ProcessInfo(qint64)> reader, std::function<QString(const ProcessInfo &, int)> signal)
{
    d->reader = std::move(reader);
    d->signal = std::move(signal);
}

void ApplicationController::setSchedulingAdapter(std::function<QString(const ProcessInfo &, int, int, int)> adapter)
{
    d->schedule = std::move(adapter);
}
