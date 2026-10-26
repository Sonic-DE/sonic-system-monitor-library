/* SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include "application_process_model.h"
#include <QObject>
#include <QVariant>
#include <functional>
#include <memory>
#include <qqmlintegration.h>

namespace KSysGuard {
/** Application actions deliberately have no privileged fallback. Captures are
 * bounded, single-use capabilities held in C++, not editable PID lists in QML. */
class PROCESSCORE_EXPORT ApplicationController : public QObject {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(KSysGuard::ApplicationProcessModel *model READ model WRITE setModel NOTIFY modelChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
public:
    explicit ApplicationController(QObject *parent = nullptr);
    ~ApplicationController() override;
    ApplicationProcessModel *model() const;
    void setModel(ApplicationProcessModel *model);
    QString statusMessage() const;
    Q_INVOKABLE QString capture(const QStringList &applicationIds);
    Q_INVOKABLE void cancel(const QString &capture);
    Q_INVOKABLE QVariantMap scheduling(const QString &capture);
    Q_INVOKABLE bool sendSignal(const QString &capture, int signal);
    Q_INVOKABLE bool applyScheduling(const QString &capture, int niceValue, int cpuScheduler, int cpuPriority, int ioScheduler, int ioPriority);
Q_SIGNALS:
    void modelChanged();
    void statusMessageChanged();

private:
    friend class ::ApplicationProcessModelTest;
    void setActionAdapters(std::function<ApplicationTracking::ProcessInfo(qint64)> reader,
                           std::function<QString(const ApplicationTracking::ProcessInfo &, int)> signal);
    void setSchedulingAdapter(std::function<QString(const ApplicationTracking::ProcessInfo &, int, int, int)> adapter);
    void setStatus(const QString &status);
    bool dispatch(const QString &capture, const std::function<QString(const ApplicationTracking::ProcessInfo &)> &action);
    class Private;
    std::unique_ptr<Private> d;
};
}
