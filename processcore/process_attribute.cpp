/*
    SPDX-FileCopyrightText: 2019 David Edmundson <davidedmundson@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "process_attribute.h"
#include "cgroup.h"
#include "formatter.h"

#include <QMetaMethod>
#include <limits>

using namespace KSysGuard;

class Q_DECL_HIDDEN KSysGuard::ProcessAttribute::Private
{
public:
    QString m_id;

    QString m_name;
    QString m_shortName;
    QString m_description;
    qreal m_min = 0;
    qreal m_max = 0;
    KSysGuard::Unit m_unit = KSysGuard::UnitInvalid; // Both a format hint and implies data type (i.e double/string)

    QHash<KSysGuard::Process *, QVariant> m_data;
    int m_watchCount = 0;

    bool m_defaultVisible = false;

    Processes::UpdateFlags m_updateFlags = Processes::StandardInformation;
    GroupAggregation m_groupAggregation = GroupAggregation::Sum;
    GroupDataFunction m_groupDataFunction;
};

ProcessAttribute::ProcessAttribute(const QString &id, QObject *parent)
    : ProcessAttribute(id, QString(), parent)
{
}

ProcessAttribute::ProcessAttribute(const QString &id, const QString &name, QObject *parent)
    : QObject(parent)
    , d(new Private)
{
    d->m_id = id;
    d->m_name = name;
}

ProcessAttribute::~ProcessAttribute()
{
}

QString ProcessAttribute::id() const
{
    return d->m_id;
}

bool ProcessAttribute::enabled() const
{
    return d->m_watchCount > 0;
}

QString ProcessAttribute::name() const
{
    return d->m_name;
}

void ProcessAttribute::setName(const QString &name)
{
    d->m_name = name;
}

QString ProcessAttribute::shortName() const
{
    return d->m_shortName.isEmpty() ? d->m_name : d->m_shortName;
}

void ProcessAttribute::setShortName(const QString &name)
{
    d->m_shortName = name;
}

QString ProcessAttribute::description() const
{
    return d->m_description;
}

void ProcessAttribute::setDescription(const QString &description)
{
    d->m_description = description;
}

qreal ProcessAttribute::min() const
{
    return d->m_min;
}

void ProcessAttribute::setMin(const qreal min)
{
    d->m_min = min;
}

qreal ProcessAttribute::max() const
{
    return d->m_max;
}

void ProcessAttribute::setMax(const qreal max)
{
    d->m_max = max;
}

KSysGuard::Unit ProcessAttribute::unit() const
{
    return d->m_unit;
}

void ProcessAttribute::setUnit(KSysGuard::Unit unit)
{
    d->m_unit = unit;
}

bool KSysGuard::ProcessAttribute::isVisibleByDefault() const
{
    return d->m_defaultVisible;
}

void KSysGuard::ProcessAttribute::setVisibleByDefault(bool visible)
{
    d->m_defaultVisible = visible;
}

Processes::UpdateFlags ProcessAttribute::requiredUpdateFlags() const
{
    return d->m_updateFlags;
}

void ProcessAttribute::setRequiredUpdateFlags(Processes::UpdateFlags flags)
{
    d->m_updateFlags = flags;
}

QVariant ProcessAttribute::data(KSysGuard::Process *process) const
{
    return d->m_data.value(process);
}

QVariant ProcessAttribute::formattedData(Process *process) const
{
    return KSysGuard::Formatter::formatValue(data(process), unit());
}

void ProcessAttribute::setData(KSysGuard::Process *process, const QVariant &value)
{
    d->m_data[process] = value;
    Q_EMIT dataChanged(process);
}

void ProcessAttribute::clearData(KSysGuard::Process *process)
{
    d->m_data.remove(process);
    Q_EMIT dataChanged(process);
}

QVariant ProcessAttribute::cgroupData(KSysGuard::CGroup *cgroup, const QList<KSysGuard::Process *> &groupProcesses) const
{
    Q_UNUSED(cgroup)

    if (d->m_groupDataFunction) {
        return d->m_groupDataFunction(groupProcesses);
    }

    if (groupProcesses.isEmpty()) {
        return QVariant{};
    }

    qreal total = std::accumulate(groupProcesses.constBegin(), groupProcesses.constEnd(), 0.0, [this](qreal total, KSysGuard::Process *process) {
        return total + data(process).toDouble();
    });
    return QVariant(total);
}

void ProcessAttribute::setGroupAggregation(GroupAggregation policy)
{
    d->m_groupAggregation = policy;
}

ProcessAttribute::GroupAggregation ProcessAttribute::groupAggregation() const
{
    return d->m_groupAggregation;
}

void ProcessAttribute::setGroupDataFunction(GroupDataFunction function)
{
    d->m_groupDataFunction = std::move(function);
}

QVariant ProcessAttribute::groupData(const QList<Process *> &processes) const
{
    const auto policy = groupAggregation();
    if (d->m_groupDataFunction) {
        return d->m_groupDataFunction(processes);
    }
    if (policy == GroupAggregation::Unsupported) {
        return {};
    }
    if (processes.isEmpty()) {
        // The legacy average is an empty sum converted to zero, divided by
        // zero. Preserve that result for existing consumers too.
        return policy == GroupAggregation::Average ? QVariant(std::numeric_limits<qreal>::quiet_NaN()) : QVariant();
    }
    if (policy == GroupAggregation::First) {
        return data(processes.first());
    }
    qreal total = 0;
    for (auto *process : processes) {
        const auto value = data(process);
        if (policy == GroupAggregation::FirstValid) {
            if (value.isValid() && !value.toString().isEmpty()) {
                return value;
            }
            continue;
        }
        // Preserve the legacy numeric conversion, including signed priorities,
        // sentinel values, and missing provider samples converted to zero.
        total += value.toDouble();
    }
    if (policy == GroupAggregation::FirstValid) {
        return {};
    }
    return policy == GroupAggregation::Average ? total / processes.size() : total;
}

void ProcessAttribute::connectNotify(const QMetaMethod &signal)
{
    if (signal != QMetaMethod::fromSignal(&ProcessAttribute::dataChanged)) {
        return;
    }
    d->m_watchCount++;
    if (d->m_watchCount == 1) {
        Q_EMIT enabledChanged(true);
    }
}

void ProcessAttribute::disconnectNotify(const QMetaMethod &signal)
{
    if (signal.isValid() && signal != QMetaMethod::fromSignal(&ProcessAttribute::dataChanged)) {
        return;
    }
    d->m_watchCount--;
    if (d->m_watchCount == 0) {
        Q_EMIT enabledChanged(false);
    }
}
