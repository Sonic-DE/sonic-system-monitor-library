/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include "application_process_model.h"
#include "application_resolver_p.h"
#include "cgroup.h"
#include "extended_process_list.h"
#include "formatter.h"
#include "process_attribute.h"
#include "process_attribute_model.h"
#include "process_data_model.h"

#include <KLocalizedString>
#include <KSycoca>
#include <KUser>
#include <QCoreApplication>
#include <QFileInfo>
#include <QMetaEnum>
#include <QSet>
#include <QTimer>
#include <algorithm>
#include <utility>

using namespace KSysGuard;
using namespace KSysGuard::ApplicationTracking;

class ApplicationProcessModel::Private {
public:
    struct Row {
        Application application;
        QList<ProcessInfo> members;
        QList<ProcessInfo> targets;
        QStringList sources;
    };
    QSharedPointer<ExtendedProcesses> processes = ExtendedProcesses::instance();
    QTimer timer;
    QTimer changes;
    QTimer sensorChanges;
    QSet<QString> dirtyApplications;
    qint64 uid = KUserId::currentEffectiveUserId().nativeId();
    DesktopIndex desktops;
    Resolver resolver;
    GroupCatalog catalog;
    QString procRoot = QStringLiteral("/proc");
    QString cgroupRoot = CGroup::cgroupSysBasePath();
    QList<Row> rows;
    QHash<QString, int> rowById;
    QHash<qint64, QString> applicationByPid;
    QHash<QString, ProcessAttribute *> attributes;
    QList<ProcessAttribute *> columns;
    ProcessAttributeModel *attributeModel = nullptr;
    QVariantList hints;
    QVariantMap overrides;
    bool available = false;
    bool rebuilding = false;
    QString status;
    std::function<QList<ProcessInfo>()> inventorySource;
    std::function<Process *(qint64)> processLookup;

    bool actionable(const Row &row) const
    {
        return row.application.id != QLatin1String("services") && !row.targets.isEmpty()
            && std::all_of(row.targets.cbegin(), row.targets.cend(), [this](const auto &p) {
                   return p.pid > 1 && p.startTime > 0 && p.uid == uid && p.euid == uid && !p.executable.isEmpty();
               });
    }
};

ApplicationProcessModel::ApplicationProcessModel(QObject *parent)
    : QAbstractItemModel(parent)
    , d(std::make_unique<Private>())
{
    for (auto *attribute : d->processes->attributes()) {
        d->attributes.insert(attribute->id(), attribute);
    }
    const QList<QPair<QString, QString>> metadata = {{QStringLiteral("appName"), i18nc("@title", "Name")},
                                                     {QStringLiteral("iconName"), i18nc("@title", "Icon")},
                                                     {QStringLiteral("menuId"), i18nc("@title", "Desktop ID")}};
    for (const auto &[id, name] : metadata) {
        d->attributes.insert(id, new ProcessAttribute(id, name, this));
    }
    d->desktops.reload();
    connect(KSycoca::self(), &KSycoca::databaseChanged, this, [this] {
        d->desktops.reload();
        d->resolver.clear();
        if (enabled()) {
            d->changes.start();
        }
    });
    d->timer.setInterval(2000);
    d->changes.setSingleShot(true);
    d->changes.setInterval(50);
    d->sensorChanges.setSingleShot(true);
    d->sensorChanges.setInterval(50);
    connect(&d->sensorChanges, &QTimer::timeout, this, [this] {
        const auto dirty = std::exchange(d->dirtyApplications, {});
        for (const auto &id : dirty) {
            const auto row = rowForApplication(id);
            if (row >= 0 && columnCount()) {
                Q_EMIT dataChanged(index(row, 0), index(row, columnCount() - 1));
            }
        }
    });
    connect(&d->timer, &QTimer::timeout, this, &ApplicationProcessModel::update);
    connect(&d->changes, &QTimer::timeout, this, &ApplicationProcessModel::rebuild);
    connect(d->processes.data(), &Processes::updated, this, [this] {
        if (enabled()) {
            d->changes.start();
        }
    });
    // Signals from providers can arrive between inventory refreshes. Coalesce
    // them without caching Process pointers that shared inventory may delete.
    d->timer.start();
    QTimer::singleShot(0, this, &ApplicationProcessModel::update);
}

ApplicationProcessModel::~ApplicationProcessModel() = default;

QModelIndex ApplicationProcessModel::index(int row, int column, const QModelIndex &parent) const
{
    return !parent.isValid() && row >= 0 && row < rowCount() && column >= 0 && column < columnCount() ? createIndex(row, column) : QModelIndex();
}

QModelIndex ApplicationProcessModel::parent(const QModelIndex &) const
{
    return {};
}

int ApplicationProcessModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : d->rows.size();
}
int ApplicationProcessModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : d->columns.size();
}
QStringList ApplicationProcessModel::availableAttributes() const
{
    return d->attributes.keys();
}
QStringList ApplicationProcessModel::enabledAttributes() const
{
    QStringList result;
    for (auto *attribute : d->columns) {
        result.append(attribute->id());
    }
    return result;
}

void ApplicationProcessModel::setEnabledAttributes(const QStringList &attributes)
{
    if (attributes == enabledAttributes()) {
        return;
    }
    beginResetModel();
    for (auto *attribute : std::as_const(d->columns)) {
        disconnect(attribute, nullptr, this, nullptr);
    }
    d->columns.clear();
    for (const auto &id : attributes) {
        if (auto *attribute = d->attributes.value(id); attribute && !d->columns.contains(attribute)) {
            d->columns.append(attribute);
        }
    }
    endResetModel();
    watchAttributes();
    Q_EMIT enabledAttributesChanged();
    if (enabled()) {
        update();
    }
}

QAbstractItemModel *ApplicationProcessModel::attributesModel()
{
    if (!d->attributeModel) {
        d->attributeModel = new ProcessAttributeModel(d->attributes.values(), this);
    }
    return d->attributeModel;
}

bool ApplicationProcessModel::enabled() const
{
    return d->timer.isActive();
}
void ApplicationProcessModel::setEnabled(bool enabled)
{
    if (enabled == this->enabled()) {
        return;
    }
    if (enabled) {
        d->timer.start();
        watchAttributes();
        update();
    } else {
        d->timer.stop();
        d->changes.stop();
        d->sensorChanges.stop();
        d->dirtyApplications.clear();
        watchAttributes();
    }
    Q_EMIT enabledChanged();
}

void ApplicationProcessModel::watchAttributes()
{
    for (auto *attribute : std::as_const(d->columns)) {
        disconnect(attribute, &ProcessAttribute::dataChanged, this, nullptr);
        if (enabled()) {
            connect(attribute, &ProcessAttribute::dataChanged, this, [this](Process *process) {
                if (process) {
                    const auto id = d->applicationByPid.value(process->pid());
                    if (!id.isEmpty()) {
                        d->dirtyApplications.insert(id);
                    }
                    if (!d->sensorChanges.isActive()) {
                        d->sensorChanges.start();
                    }
                }
            });
        }
    }
}
bool ApplicationProcessModel::available() const
{
    return d->available;
}
QString ApplicationProcessModel::statusMessage() const
{
    return d->status;
}
QVariantList ApplicationProcessModel::identityHints() const
{
    return d->hints;
}
void ApplicationProcessModel::setIdentityHints(const QVariantList &hints)
{
    if (hints == d->hints) {
        return;
    }
    d->hints = hints;
    if (enabled()) {
        d->changes.start();
    }
    Q_EMIT identityHintsChanged();
}
QVariantMap ApplicationProcessModel::applicationOverrides() const
{
    return d->overrides;
}
void ApplicationProcessModel::setApplicationOverrides(const QVariantMap &overrides)
{
    if (overrides == d->overrides) {
        return;
    }
    d->overrides = overrides;
    if (!d->rows.isEmpty() && !d->columns.isEmpty()) {
        Q_EMIT dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
    }
    Q_EMIT applicationOverridesChanged();
}

QHash<int, QByteArray> ApplicationProcessModel::roleNames() const
{
    auto roles = QAbstractItemModel::roleNames();
    const auto enumeration = QMetaEnum::fromType<ProcessDataModel::AdditionalRoles>();
    for (int i = 0; i < enumeration.keyCount(); ++i) {
        roles.insert(enumeration.value(i), enumeration.key(i));
    }
    roles.insert(ApplicationId, "ApplicationId");
    roles.insert(ActionEligible, "ActionEligible");
    roles.insert(Attribution, "Attribution");
    roles.insert(ActionPIDs, "ActionPIDs");
    roles.insert(GroupOrigins, "GroupOrigins");
    return roles;
}

QVariant ApplicationProcessModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || section < 0 || section >= d->columns.size()) {
        return {};
    }
    auto *attribute = d->columns.at(section);
    switch (role) {
    case Qt::DisplayRole:
    case ProcessDataModel::ShortName:
        return attribute->shortName();
    case ProcessDataModel::Name:
        return attribute->name();
    case ProcessDataModel::Value:
    case ProcessDataModel::Attribute:
        return attribute->id();
    case ProcessDataModel::Unit:
        return attribute->unit();
    case ProcessDataModel::Minimum:
        return attribute->min();
    case ProcessDataModel::Maximum:
        return attribute->max();
    case ProcessDataModel::UpdateInterval:
        return 2000;
    default:
        return {};
    }
}

QVariant ApplicationProcessModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.model() != this || index.row() >= rowCount() || index.column() >= columnCount()) {
        return {};
    }
    const auto &row = d->rows.at(index.row());
    if (role == ApplicationId) {
        return row.application.id;
    }
    if (role == ActionEligible) {
        return d->actionable(row);
    }
    if (role == Attribution) {
        return row.sources;
    }
    if (role == GroupOrigins) {
        return row.application.origins;
    }
    auto *attribute = d->columns.at(index.column());
    if (role == ProcessDataModel::PIDs || role == ActionPIDs) {
        QVariantList result;
        for (const auto &member : role == ActionPIDs ? row.targets : row.members) {
            result.append(member.pid);
        }
        return result;
    }
    if (role != Qt::DisplayRole && role != ProcessDataModel::Value && role != ProcessDataModel::FormattedValue) {
        return headerData(index.column(), Qt::Horizontal, role);
    }
    const auto id = attribute->id();
    const auto overrides = d->overrides.value(row.application.id).toMap();
    QVariant value;
    if (overrides.contains(id)) {
        value = overrides.value(id);
    } else if (id == QLatin1String("appName")) {
        value = row.application.id == QLatin1String("services")        ? i18nc("@label", "Background Services")
            : row.application.name.isEmpty() && !row.members.isEmpty() ? i18nc("@label", "Process %1", row.members.first().pid)
                                                                       : row.application.name;
    } else if (id == QLatin1String("iconName")) {
        value = row.application.icon;
    } else if (id == QLatin1String("menuId")) {
        value = row.application.menuId;
    } else {
        QList<Process *> members;
        for (const auto &member : row.members) {
            auto *process = d->processLookup ? d->processLookup(member.pid) : d->processes->getProcess(member.pid);
            if (!process || process->startTime() != member.startTime || process->uid() != member.uid || process->euid() != member.euid) {
                return {};
            }
            members.append(process);
        }
        value = attribute->groupData(members);
    }
    return role == ProcessDataModel::Value ? value : Formatter::formatValue(value, attribute->unit());
}

void ApplicationProcessModel::update()
{
    if (!enabled() || d->rebuilding) {
        return;
    }
    if (!d->inventorySource && d->procRoot == QLatin1String("/proc")) {
        Processes::UpdateFlags flags = Processes::StandardInformation;
        for (auto *attribute : std::as_const(d->columns)) {
            flags |= attribute->requiredUpdateFlags();
        }
        d->processes->updateAllProcesses(2000, flags);
    }
    d->changes.stop();
    rebuild();
}

void ApplicationProcessModel::rebuild()
{
    if (!enabled() || d->rebuilding) {
        return;
    }
    d->rebuilding = true;
    QList<ProcessInfo> inventory;
    bool restricted = false;
    const auto self = QCoreApplication::applicationPid();
    const bool fixtureInventory = d->procRoot != QLatin1String("/proc");
    // Enumeration can work while individual identity files are restricted.
    // Do not discard an otherwise usable inventory on an identity-probe failure.
    const bool available = d->inventorySource
        || (fixtureInventory ? QFileInfo(d->procRoot).isDir() && QFileInfo(d->procRoot).isReadable() : d->processes->getProcess(self) != nullptr);
    if (d->inventorySource) {
        inventory = d->inventorySource();
    } else if (fixtureInventory && available) {
        inventory = readProcessInventory(d->procRoot);
    } else if (available) {
        for (auto *process : d->processes->getAllProcesses()) {
            if (process->pid() <= 1) {
                continue;
            }
            if (process->uid() != d->uid) {
                // Preserve only ownership/boundary information for foreign
                // parents and group peers; never collect executable/command
                // metadata. PGID/SID are needed for detached privileged jobs.
                auto info = readProcessGroupIdentity(process->pid());
                if (info.pid <= 1) {
                    info = {process->pid(), process->parentPid(), process->startTime(), process->uid(), process->euid(), {}, {}, process->cGroup()};
                }
                if (info.uid < 0) {
                    info.uid = process->uid();
                }
                if (info.euid < 0) {
                    info.euid = process->euid();
                }
                if (info.uid == d->uid) {
                    // Ownership may have changed since the shared sample. Only
                    // enrich executable/name information after verifying it is
                    // now a current-user process.
                    const auto owned = readProcess(process->pid());
                    if (owned.pid > 1 && owned.uid == d->uid) {
                        info = owned;
                    }
                }
                inventory.append(info);
                continue;
            }
            auto info = readProcess(process->pid());
            if (info.pid <= 1) {
                info = {process->pid(), process->parentPid(), process->startTime(), process->uid(), process->euid(), {}, process->name(), process->cGroup()};
            }
            if (info.uid != d->uid) {
                info.name.clear();
                info.executable.clear();
            }
            restricted = restricted || info.executable.isEmpty();
            inventory.append(info);
        }
    }
    for (const auto &process : std::as_const(inventory)) {
        restricted = restricted || process.uid < 0 || process.startTime <= 0;
    }
    d->catalog = discoverGroups(d->cgroupRoot, d->uid, inventory);
    const auto assigned = d->resolver.resolve(inventory, d->uid, d->hints, d->desktops, d->catalog);
    QMap<QString, Private::Row> groups;
    for (const auto &app : std::as_const(d->catalog.applications)) {
        groups[app.id].application = app;
    }
    d->applicationByPid.clear();
    for (const auto &assignment : assigned) {
        restricted = restricted || assignment.process.startTime <= 0 || (assignment.process.uid == d->uid && assignment.process.executable.isEmpty());
        auto &row = groups[assignment.application.id];
        row.application = assignment.application;
        if (d->catalog.applications.contains(assignment.application.id)) {
            row.application.origins = d->catalog.applications.value(assignment.application.id).origins;
        }
        row.members.append(assignment.process);
        if (assignment.actionEligible) {
            row.targets.append(assignment.process);
        }
        if (!row.sources.contains(assignment.source)) {
            row.sources.append(assignment.source);
        }
        d->applicationByPid.insert(assignment.process.pid, assignment.application.id);
    }
    for (int row = d->rows.size() - 1; row >= 0; --row) {
        if (!groups.contains(d->rows.at(row).application.id)) {
            beginRemoveRows({}, row, row);
            d->rows.removeAt(row);
            endRemoveRows();
        }
    }
    QSet<QString> present;
    for (auto &row : d->rows) {
        const auto id = row.application.id;
        row = groups.value(id);
        present.insert(id);
    }
    for (auto it = groups.cbegin(); it != groups.cend(); ++it) {
        if (!present.contains(it.key())) {
            const auto row = d->rows.size();
            beginInsertRows({}, row, row);
            d->rows.append(it.value());
            endInsertRows();
        }
    }
    d->rowById.clear();
    for (int row = 0; row < d->rows.size(); ++row) {
        d->rowById.insert(d->rows.at(row).application.id, row);
    }
    const QString status = !available ? i18n("Process information is unavailable. Check access to procfs.")
        : !d->catalog.issues.isEmpty()
        ? i18n("Some application-group metadata is incomplete. The process inventory remains available without desktop-scope filtering.")
        : restricted ? i18n("Some process identities are inaccessible. Their grouping or measurements may be incomplete.")
                     : QString();
    if (available != d->available || status != d->status) {
        d->available = available;
        d->status = status;
        Q_EMIT statusChanged();
    }
    if (rowCount() && columnCount()) {
        Q_EMIT dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
    }
    d->rebuilding = false;
    Q_EMIT applicationsChanged();
}

int ApplicationProcessModel::rowForApplication(const QString &id) const
{
    // Row notifications can synchronously evaluate QML selection bindings while
    // the lookup table is being rebuilt. Never expose an old row for a new ID.
    if (d->rebuilding) {
        for (int row = 0; row < d->rows.size(); ++row) {
            if (d->rows.at(row).application.id == id) {
                return row;
            }
        }
        return -1;
    }
    return d->rowById.value(id, -1);
}

QVariantMap ApplicationProcessModel::processIdentity(qint64 pid) const
{
    const auto info = readProcess(pid);
    if (info.pid <= 1 || info.uid != d->uid || info.executable.isEmpty()) {
        return {};
    }
    return {{QStringLiteral("pid"), info.pid}, {QStringLiteral("startTime"), QString::number(info.startTime)}};
}

QVariantList ApplicationProcessModel::captureTargets(const QStringList &ids) const
{
    QVariantList result;
    if (ids.isEmpty() || d->rebuilding) {
        return result;
    }
    auto uniqueIds = ids;
    uniqueIds.removeDuplicates();
    for (const auto &id : uniqueIds) {
        const auto rowIndex = rowForApplication(id);
        if (rowIndex < 0 || !d->actionable(d->rows.at(rowIndex))) {
            return {}; // Reject a mixed selection as a whole.
        }
        for (const auto &member : d->rows.at(rowIndex).targets) {
            result.append(QVariantMap{{QStringLiteral("applicationId"), id},
                                      {QStringLiteral("pid"), member.pid},
                                      {QStringLiteral("startTime"), QString::number(member.startTime)},
                                      {QStringLiteral("executable"), member.executable}});
        }
    }
    return result;
}

bool ApplicationProcessModel::containsTarget(const QVariantMap &target) const
{
    const auto id = target.value(QStringLiteral("applicationId")).toString();
    const auto row = rowForApplication(id);
    if (row < 0 || !d->actionable(d->rows.at(row))) {
        return false;
    }
    return std::any_of(d->rows.at(row).targets.cbegin(), d->rows.at(row).targets.cend(), [&target](const auto &member) {
        return member.pid == target.value(QStringLiteral("pid")).toLongLong() && member.startTime == target.value(QStringLiteral("startTime")).toLongLong()
            && member.executable == target.value(QStringLiteral("executable")).toString();
    });
}

void ApplicationProcessModel::setInventorySource(std::function<QList<ProcessInfo>()> source)
{
    d->inventorySource = std::move(source);
    d->cgroupRoot.clear(); // Pure injected snapshots do not mix with host groups.
}

void ApplicationProcessModel::setProcessLookup(std::function<Process *(qint64)> lookup)
{
    d->processLookup = std::move(lookup);
}

void ApplicationProcessModel::setDiscoveryRoots(const QString &procRoot, const QString &cgroupRoot)
{
    d->inventorySource = {};
    d->procRoot = procRoot;
    d->cgroupRoot = cgroupRoot;
    d->resolver.clear();
}
