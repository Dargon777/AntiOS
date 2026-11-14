# AntiOS 3.0.05 Alpha

## Changes

- Resident Guard detaches from its console when running in the background. Closing that console no longer interrupts file monitoring. The status, history and stop commands still work from a terminal.
- When SQLite recreates its journal files, they inherit the current user's access so the Windows dashboard can read Guard status without elevation.
- The scan coverage window shows which files were affected by scan limits and skipped checks. Incident evidence uses the observed process ID and creation time when available.
- Signed catalogs can be compared offline with whole-file hashes from an earlier scan report. Hashes of clean files are included when explicitly requested. Archive member hashes require a fresh scan.
- Guard keeps findings visible and defers automatic quarantine when the local trust baseline conflicts, is unreadable, or the scan worker was interrupted.

Guard monitors selected folders after changes. System-wide pre-execution blocking remains unavailable. Windows packages are unsigned. See [release verification](../docs/SIGNING.md).

## По-русски

- Фоновый Guard продолжает работу после закрытия консоли. Команды просмотра состояния, журнала и остановки доступны в терминале.
- Вновь созданные служебные файлы SQLite наследуют права текущего пользователя. Интерфейс может читать состояние Guard без повышения прав.
- Окно покрытия показывает ограничения сканирования и затронутые файлы. Граф инцидентов использует PID и время создания процесса, когда эти данные доступны.
- Подписанную базу можно сверить с хэшами из предыдущего отчёта. Хэши чистых файлов добавляются по запросу. Вложения архивов требуют новой проверки.
- При конфликте с доверенным списком, недоступности списка или прерванном сканировании Guard сохраняет находку для ручной проверки и откладывает автоматический карантин.

Guard реагирует на изменения в выбранных папках. Системная блокировка до запуска недоступна. Windows-сборки без подписи издателя. [Проверка происхождения сборки](../docs/SIGNING.md).
