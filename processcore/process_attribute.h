/*
    SPDX-FileCopyrightText: 2019 David Edmundson <davidedmundson@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/
#pragma once

#include <QObject>
#include <QVariant>
#include <functional>

#include "processes.h"
#include "unit.h"

#include "processcore_export.h"

namespace KSysGuard
{
class Process;
class CGroup;

class PROCESSCORE_EXPORT ProcessAttribute : public QObject
{
    Q_OBJECT
public:
    ProcessAttribute(const QString &id, QObject *parent);
    ProcessAttribute(const QString &id, const QString &name, QObject *parent);

    ~ProcessAttribute() override;

    /**
     * A unique non-translatable ID for this attribute. For saving in config files
     */
    QString id() const;

    /**
     * States whether we should update process attributes
     */
    bool enabled() const;

    /**
     * A translated user facing name for the attribute.
     * e.g "Download Speed"
     */
    QString name() const;
    void setName(const QString &name);

    /**
     * A translated shorter version of the name
     * for use in table column headers for example
     * e.g "D/L"
     * If unset, name is returned
     */
    QString shortName() const;
    void setShortName(const QString &name);

    /**
     * A translated human readable description of this attribute
     */
    QString description() const;
    void setDescription(const QString &description);

    /**
     * The minimum value possible for this sensor
     * (i.e to show a CPU is between 0 and 100)
     * Set min and max to 0 if not relevant
     */
    qreal min() const;
    void setMin(const qreal min);
    /**
     * The maximum value possible for this attribute
     */
    qreal max() const;
    void setMax(const qreal max);

    KSysGuard::Unit unit() const;
    void setUnit(KSysGuard::Unit unit);

    /**
     * A hint to UIs that this sensor would like to be visible by default.
     *
     * Defaults to false.
     */
    bool isVisibleByDefault() const;
    void setVisibleByDefault(bool visible);

    /**
     * Which update steps are required for this attribute to correctly report its data.
     *
     * This can be used to determine which flags should be used when calling
     * Processes::updateAllProcesses() . By default this will be
     * Processess::StandardInformation.
     */
    Processes::UpdateFlags requiredUpdateFlags() const;
    void setRequiredUpdateFlags(Processes::UpdateFlags flags);

    /**
     * The last stored value for a given process
     */
    virtual QVariant data(KSysGuard::Process *process) const;

    /**
     * The last stored value for a given process, formatted by its unit
     */
    virtual QVariant formattedData(KSysGuard::Process *process) const;

    /**
     * Updates the stored value for a given process
     * Note stray processes will be automatically expunged
     */
    void setData(KSysGuard::Process *process, const QVariant &value);
    /**
     * Remove an attribute from our local cache
     */
    void clearData(KSysGuard::Process *process);

    virtual QVariant cgroupData(KSysGuard::CGroup *cgroup, const QList<KSysGuard::Process *> &groupProcesses = {}) const;

    /** Process-list aggregation, independent of cgroup identity. The default
     * numeric sum matches the legacy base cgroupData implementation, including
     * signed values. Custom providers can share a callback between both paths;
     * no cgroupData override is called with a synthetic or null cgroup.
     * These nonvirtual additions preserve the exported virtual layout. */
    enum class GroupAggregation {
        Unsupported,
        Sum,
        Average,
        First,
        FirstValid
    };
    void setGroupAggregation(GroupAggregation policy);
    GroupAggregation groupAggregation() const;
    using GroupDataFunction = std::function<QVariant(const QList<KSysGuard::Process *> &)>;
    void setGroupDataFunction(GroupDataFunction function);
    QVariant groupData(const QList<KSysGuard::Process *> &processes) const;

Q_SIGNALS:
    void dataChanged(KSysGuard::Process *process);
    void enabledChanged(bool enabled);

protected:
    void connectNotify(const QMetaMethod &signal) override;
    void disconnectNotify(const QMetaMethod &signal) override;

private:
    class Private;
    QScopedPointer<Private> d;
};

}
