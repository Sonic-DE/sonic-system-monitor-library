/* SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "processcore_export.h"
#include <QAbstractItemModel>
#include <QVariant>
#include <functional>
#include <memory>
#include <qqmlintegration.h>

class ApplicationProcessModelTest;
class ApplicationDiscoveryTest;

namespace KSysGuard {
class ProcessAttributeModel;
class Process;
class ApplicationController;
namespace ApplicationTracking {
struct ProcessInfo;
}

/** Init-independent, current-user application accounting. Window identity is
 * supplied by the GUI; process discovery and accounting never require it. */
class PROCESSCORE_EXPORT ApplicationProcessModel : public QAbstractItemModel {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QStringList availableAttributes READ availableAttributes CONSTANT)
    Q_PROPERTY(QStringList enabledAttributes READ enabledAttributes WRITE setEnabledAttributes NOTIFY enabledAttributesChanged)
    Q_PROPERTY(QAbstractItemModel *attributesModel READ attributesModel CONSTANT)
    Q_PROPERTY(bool enabled READ enabled WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(bool available READ available NOTIFY statusChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusChanged)
    Q_PROPERTY(QVariantList identityHints READ identityHints WRITE setIdentityHints NOTIFY identityHintsChanged)
    Q_PROPERTY(QVariantMap applicationOverrides READ applicationOverrides WRITE setApplicationOverrides NOTIFY applicationOverridesChanged)

public:
    enum ApplicationRoles {
        ApplicationId = Qt::UserRole + 100,
        ActionEligible,
        Attribution,
        ActionPIDs,
        GroupOrigins
    };
    Q_ENUM(ApplicationRoles)

    explicit ApplicationProcessModel(QObject *parent = nullptr);
    ~ApplicationProcessModel() override;
    QModelIndex index(int row, int column, const QModelIndex &parent = {}) const override;
    QModelIndex parent(const QModelIndex &index) const override;
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;
    QStringList availableAttributes() const;
    QStringList enabledAttributes() const;
    void setEnabledAttributes(const QStringList &attributes);
    QAbstractItemModel *attributesModel();
    bool enabled() const;
    void setEnabled(bool enabled);
    bool available() const;
    QString statusMessage() const;
    QVariantList identityHints() const;
    void setIdentityHints(const QVariantList &hints);
    QVariantMap applicationOverrides() const;
    void setApplicationOverrides(const QVariantMap &overrides);

    Q_INVOKABLE int rowForApplication(const QString &id) const;
    // Capture a local process incarnation for a window hint. No PID-only hints.
    Q_INVOKABLE QVariantMap processIdentity(qint64 pid) const;
    // The captured target set must be intersected with current membership at
    // dispatch, never regenerated after a confirmation dialog.
    Q_INVOKABLE QVariantList captureTargets(const QStringList &applicationIds) const;
    Q_INVOKABLE void update();

Q_SIGNALS:
    void enabledAttributesChanged();
    void enabledChanged();
    void statusChanged();
    void identityHintsChanged();
    void applicationOverridesChanged();
    void applicationsChanged();

private:
    friend class ::ApplicationProcessModelTest;
    friend class ::ApplicationDiscoveryTest;
    friend class ApplicationController;
    void rebuild();
    void watchAttributes();
    bool containsTarget(const QVariantMap &target) const;
    void setInventorySource(std::function<QList<ApplicationTracking::ProcessInfo>()> source);
    void setProcessLookup(std::function<Process *(qint64)> lookup);
    void setDiscoveryRoots(const QString &procRoot, const QString &cgroupRoot);
    class Private;
    std::unique_ptr<Private> d;
};
}
