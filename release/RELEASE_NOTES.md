# AntiOS v2.0.0 alpha 18

Alpha 18 makes AntiOS behave like a resident antivirus instead of a window that
disappears when you press Close.

Closing the dashboard now sends it to the system tray. The tray menu can reopen
the same window or exit the AntiOS interface explicitly, so active scans are not
accidentally killed by closing the window.

Resident Guard and the dashboard coordinate tray ownership: while the dashboard
is alive it owns the AntiOS tray icon; when the interface exits, Guard takes the
tray back. This avoids duplicate AntiOS icons.

Icon state now has one meaning everywhere. Green means Resident Guard is
actively monitoring or scanning. Red is reserved for attention, degraded,
failed, unresponsive, stopped or missing protection states. The taskbar/window
icon follows the same rule instead of being permanently red.
