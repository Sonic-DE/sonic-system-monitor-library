/*
    SPDX-FileCopyrightText: 2026 SonicDE contributors

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <QTemporaryFile>
#include <QTest>

#include "processcore/plugins/gpu/gpu.h"

class GpuFdinfoTest : public QObject {
    Q_OBJECT

private Q_SLOTS:
    void memory_data();
    void memory();
};

void GpuFdinfoTest::memory_data()
{
    QTest::addColumn<QByteArray>("fdinfo");
    QTest::addColumn<uint32_t>("memoryKiB");

    const QByteArray intel = "drm-driver: i915\ndrm-engine-render: 100000000 ns\n";
    const QByteArray amd = "drm-driver: amdgpu\ndrm-engine-gfx: 100000000 ns\n";

    QTest::newRow("intel-system-total") << intel + "drm-total-system0: 65536 KiB\n" << uint32_t(65536);
    QTest::newRow("intel-local-total") << intel + "drm-total-local0: 65536 KiB\n" << uint32_t(65536);
    QTest::newRow("intel-resident-only") << intel + "drm-resident-system0: 65536 KiB\n" << uint32_t(65536);
    QTest::newRow("intel-total-before-resident") << intel + "drm-total-local0: 65536 KiB\ndrm-resident-local0: 32768 KiB\n" << uint32_t(65536);
    QTest::newRow("intel-resident-before-total") << intel + "drm-resident-local0: 32768 KiB\ndrm-total-local0: 65536 KiB\n" << uint32_t(65536);
    QTest::newRow("intel-multiple-regions") << intel + "drm-total-system0: 16 MiB\ndrm-total-local0: 32768 KiB\n"
                                                      "drm-resident-system0: 8192 KiB\ndrm-resident-local0: 16384 KiB\n"
                                                      "drm-shared-local0: 8192 KiB\ndrm-active-local0: 16384 KiB\n"
                                          << uint32_t(49152);
    QTest::newRow("intel-per-region-fallback") << intel + "drm-total-system0: 16384 KiB\ndrm-resident-system0: 8192 KiB\n"
                                                        "drm-resident-local0: 32768 KiB\n"
                                              << uint32_t(49152);
    QTest::newRow("intel-zero-total-is-present") << intel + "drm-total-system0: 0 KiB\ndrm-resident-system0: 16384 KiB\n"
                                                          "drm-total-local0: 32768 KiB\n"
                                                << uint32_t(32768);
    QTest::newRow("intel-bytes-driver-last") << QByteArray("drm-total-system0: 67108864\n") + intel << uint32_t(65536);
    QTest::newRow("amd-legacy-vram") << amd + "drm-memory-vram: 65536 KiB\n" << uint32_t(65536);
    QTest::newRow("amd-alias-deduplication") << amd + "drm-total-vram: 65536 KiB\ndrm-resident-vram: 65536 KiB\n"
                                                   "drm-memory-vram: 65536 KiB\n"
                                            << uint32_t(65536);
}

void GpuFdinfoTest::memory()
{
    QFETCH(QByteArray, fdinfo);
    QFETCH(uint32_t, memoryKiB);

    QTemporaryFile file;
    QVERIFY(file.open());
    QCOMPARE(file.write(fdinfo), fdinfo.size());
    QVERIFY(file.flush());

    GpuFd sample;
    QVERIFY(GpuPlugin::processPidEntry(fs::path(file.fileName().toStdString()), sample));
    QCOMPARE(sample.gfx, uint64_t(100000000));
    QCOMPARE(sample.vram, memoryKiB);
}

QTEST_GUILESS_MAIN(GpuFdinfoTest)

#include "gpufdinfotest.moc"
