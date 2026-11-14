# AntiOS 3.0.04 Alpha

- Resident Guard reads Windows file notifications during scans and reports backlogs and inventory limits. It rechecks files that change while being scanned.
- The Guard startup helper recognizes localized Windows account names and can restart the installed task using its existing policy. Startup verification requires a live heartbeat to advance.
- Windows quarantine preserves access to earlier encrypted records when more files are isolated. Automatic isolation pauses when the scanner or its installed signature catalog is degraded.
- Signed signature updates can be checked against a local baseline of trusted file hashes. A conflict blocks activation and preserves the previous catalog. The baseline does not exempt a file from scanning.
- TAR and TGZ inspection now supports standard PAX metadata and GNU long paths. Five exact CISA AR25-261A indicators bring the bundled set to 124 active hashes including the EICAR test rule.
- The Windows memory sensor checks a bounded sample of thread start addresses for private executable memory. Findings go to review, and the report shows coverage limits.

Guard monitors chosen folders after file changes. This alpha has no system-wide pre-execution blocking. The Windows downloads are unsigned. See [release verification](../docs/SIGNING.md).

## Русский

- Guard продолжает читать уведомления Windows во время сканирования, показывает очередь и пределы охвата, повторно проверяет файлы, изменившиеся при сканировании.
- Исправлено распознавание локализованных имён пользователей Windows. При восстановлении запуска Guard сохраняет выбранные папки и режим. Запуск подтверждается обновлением сигнала активности.
- Карантин сохраняет доступ к предыдущим зашифрованным записям. При сбое движка или переходе на резервную базу автоматическая изоляция приостанавливается.
- Подписанное обновление базы можно проверить на локальном наборе доверенных файлов. При конфликте продолжает работать прежняя база. Доверенные файлы по-прежнему сканируются.
- Добавлена проверка вложений TAR и TGZ с заголовками PAX и длинными путями GNU. Во встроенной базе 124 точных хэша, включая EICAR и пять новых индикаторов CISA.
- Датчик памяти проверяет адреса запуска потоков в пределах доступных процессов и показывает ограничения. Подозрительные находки идут на ручную проверку.

Guard реагирует на изменения в выбранных папках. Блокировка запуска во всей системе отсутствует. У Windows-сборок нет подписи издателя. [Проверка происхождения сборок](../docs/SIGNING.md).
