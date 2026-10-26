/* SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "processcore_export.h"
#include <QHash>
#include <QMap>
#include <QVariant>

namespace KSysGuard::ApplicationTracking {
// Private implementation API, exported only for unit tests. Never persist a
// Process pointer or identify an incarnation by PID alone.
struct ProcessInfo {
    qint64 pid = -1;
    qint64 parentPid = -1;
    qint64 startTime = -1;
    qint64 uid = -1;
    qint64 euid = -1;
    QString executable;
    QString name;
    QString cgroup;
    qint64 processGroupId = -1;
    qint64 sessionId = -1;
};

struct Application {
    QString id;
    QString name;
    QString icon;
    QString menuId;
    bool boundary = false;
    bool terminal = false;
    QStringList origins = {};
};

struct Assignment {
    ProcessInfo process;
    Application application;
    QString source;
    bool actionEligible = true;
};

struct GroupBinding {
    QString applicationId;
    qint64 startTime = -1;
};

/** Optional kernel group metadata, never an availability requirement. A complete
 * legacy desktop scope preserves its membership exactly; incomplete/missing
 * metadata cannot hide processes from the independent inventory. */
struct GroupCatalog {
    bool available = false;
    bool complete = false;
    QMap<QString, Application> applications;
    QMap<qint64, GroupBinding> bindings;
    QStringList issues;
};

class PROCESSCORE_EXPORT DesktopIndex {
public:
    void reload();
    // Tests supply deterministic desktop records, without the user's database.
    void add(const Application &application, const QString &executable, const QString &windowClass = {}, bool discoverByExecutable = true);
    Application byId(QString id) const;
    Application byExecutable(const QString &executable) const;
    Application byWindowClass(const QString &windowClass) const;

private:
    QHash<QString, Application> m_applications;
    QHash<QString, QStringList> m_executables;
    QHash<QString, QStringList> m_classes;
};

class PROCESSCORE_EXPORT Resolver {
public:
    QMap<qint64, Assignment>
    resolve(const QList<ProcessInfo> &processes, qint64 uid, const QVariantList &hints, const DesktopIndex &desktops, const GroupCatalog &catalog = {});
    void clear();

private:
    QMap<qint64, Assignment> m_previous;
};

PROCESSCORE_EXPORT ProcessInfo readProcess(qint64 pid, const QString &procRoot = QStringLiteral("/proc"));
PROCESSCORE_EXPORT ProcessInfo readProcessGroupIdentity(qint64 pid, const QString &procRoot = QStringLiteral("/proc"));
PROCESSCORE_EXPORT QList<ProcessInfo> readProcessInventory(const QString &procRoot);
PROCESSCORE_EXPORT QString readExecutable(qint64 pid, const QString &procRoot = QStringLiteral("/proc"));
PROCESSCORE_EXPORT bool isBoundaryExecutable(const QString &executable);
PROCESSCORE_EXPORT bool isTerminalExecutable(const QString &executable);
PROCESSCORE_EXPORT GroupCatalog discoverGroups(const QString &cgroupRoot, qint64 uid, const QList<ProcessInfo> &processes);
}
