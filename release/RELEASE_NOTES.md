# AntiOS 3.0.03 Alpha

This prerelease improves the Windows security-evidence surfaces and makes release provenance checks stricter. It builds on the AntiOS Engine and scan workflow introduced in 3.0.02 Alpha.

## What's new

- Expanded read-only Windows process evidence: more reliable process identity, integrity level, a bounded loaded-module inventory, and Authenticode status of on-disk images.
- Improved persistence review and correlation of related findings in the existing risk and incident views.
- Added bounded scanning of Zstandard, LZMA, DEB, RPM payloads and newc/CRC CPIO, plus advisory checks for PDF, RTF and SVG.
- Added 51 exact SHA-256 indicators since 3.0.02 Alpha. The bundled catalog now has 119 active rules including the EICAR test rule.
- Added a Rust static core to standard Windows packages, optional CUDA hashing modes and browser, network and hardware inventory.
- Added bounded evidence for process memory, driver trust and known vulnerable drivers, and Windows boot/platform security posture.
- Kept partial coverage visible. Missing evidence is **not** a clean verdict, and weak heuristic signals do not independently trigger quarantine.
- Streamlined CI workflows, refreshed public documentation, and hardened GitHub build-provenance checks for unsigned prereleases.

These sensors supply review context, **not** a claim of complete memory inspection, full system persistence coverage or guaranteed malware detection.

## Downloads and signing

The release is intended to include Windows x64 Setup and portable ZIP, Linux x86_64 archive and Python distributions.

Windows binaries in this prerelease are **unsigned**. SHA-256 checksums verify file integrity only. GitHub build attestations are checked against the release commit and `master` workflow to establish build provenance; they do **not** prove Windows publisher identity. Windows SmartScreen may warn and Smart App Control may block unsigned files. See [Signing](../docs/SIGNING.md).

## Upgrading

If upgrading from a legacy 2.x installation, follow [Installer migration](../docs/INSTALLER.md) rather than manually deleting old services or registrations.

## Русский

AntiOS 3.0.03 Alpha расширяет сбор сведений о безопасности Windows и усиливает проверку происхождения релизных сборок.

- Улучшен сбор метаданных процессов: идентификация, уровень целостности, ограниченная проверка загруженных модулей и статуса подписи файлов на диске.
- Улучшен анализ закрепления в системе и сопоставление связанных событий.
- Добавлена проверка содержимого Zstandard, LZMA, DEB, полезной нагрузки RPM и CPIO newc/CRC. Для PDF, RTF и SVG добавлены признаки для ручной проверки.
- Добавлена 51 точная SHA-256 сигнатура с версии 3.0.02 Alpha. Во встроенном наборе 119 активных правил, включая тестовое правило EICAR.
- В стандартных Windows-сборках подключён статический модуль Rust. Добавлены режимы CUDA, сбор сведений о браузерах, сети и оборудовании.
- Добавлены ограниченные диагностические данные о памяти процессов, доверии к драйверам и состоянии механизмов защиты Windows.
- Недоступные или неполные данные не выдаются за успешную проверку; слабые эвристические признаки сами по себе не приводят к карантину.
- Упрощены CI-процессы, обновлена документация и усилена проверка происхождения неподписанных сборок.

Это **не** полная проверка памяти, всех механизмов закрепления или гарантия обнаружения вредоносного ПО.

Сборки Windows **не имеют цифровой подписи издателя**. Контрольные суммы SHA-256 подтверждают целостность, а GitHub Attestations — происхождение сборки из определённого коммита и workflow, но не личность издателя Windows.
