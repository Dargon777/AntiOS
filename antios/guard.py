"""Resident, current-user post-write detection. Never claims pre-execution blocking."""
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import threading
import time
import uuid

from .antivirus import checked_path, fingerprint, is_link
from .clamav import ClamAVScanner
from .guard_notifications import ChangeBatch, DirectoryNotifications, PollNotifications
from .guard_state import GuardState, default_guard_path, read_guard_state
from .quarantine import Quarantine, default_quarantine_path
from .scan_process import run_scan_process


@dataclass(frozen=True)
class GuardPolicy:
    roots: tuple[Path, ...]
    auto_quarantine: bool = False
    interval: float = 2
    settle: float = 1
    rescan: float = 900
    max_files: int = 50000
    max_queue: int = 256
    engine_service: str | None = None

    def validate(self):
        if not 1 <= len(self.roots) <= 16:
            raise ValueError('Select 1..16 directories')
        if not 0.1 <= self.interval <= 60 or not 0 <= self.settle <= 10 or not 30 <= self.rescan <= 86400:
            raise ValueError('Invalid guard time limits')
        if not 1 <= self.max_files <= 100000 or not 1 <= self.max_queue <= 4096:
            raise ValueError('Invalid guard capacity limits')
        if self.engine_service is not None:
            from .windows_clamd_peer import validate_service_name
            validate_service_name(self.engine_service)
        roots = tuple(dict.fromkeys(checked_path(root) for root in self.roots))
        if any(not root.is_dir() for root in roots):
            raise ValueError('Guard roots must be directories')
        if os.name == 'nt' and any(str(root).startswith('\\\\') for root in roots):
            raise ValueError('Guard does not support network roots')
        return roots


def file_identity(info):
    return (*fingerprint(info), info.st_ctime_ns)


def inventory(roots, *, excluded=(), max_files=50000, cancelled=lambda: False):
    """Reconcile notifications against disk, with bounded traversal and no links."""
    files, issues, stack = {}, [], list(roots)
    entries = 0
    limited = False
    while stack and not cancelled():
        folder = stack.pop()
        if any(folder == root or root in folder.parents for root in excluded):
            continue
        try:
            checked_path(folder)
            with os.scandir(folder) as children:
                for child in children:
                    if cancelled():
                        return files, issues, True
                    entries += 1
                    if entries > max_files * 2 or len(files) >= max_files:
                        return files, issues, True
                    path = Path(child.path)
                    if any(path == root or root in path.parents for root in excluded):
                        continue
                    try:
                        # Windows DirEntry.stat may omit file IDs. Use the same stat
                        # source as post-scan validation so stable files can be cached.
                        info = path.stat(follow_symlinks=False) if os.name == 'nt' else child.stat(follow_symlinks=False)
                        if is_link(info):
                            raise ValueError('link-or-reparse-point')
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(path)
                        elif stat.S_ISREG(info.st_mode):
                            files[path] = file_identity(info)
                        else:
                            raise ValueError('not-a-regular-file')
                    except (OSError, ValueError) as exc:
                        if len(issues) < 100:
                            issues.append({'path': str(path), 'reason': str(exc)[:500]})
        except (OSError, ValueError) as exc:
            if len(issues) < 100:
                issues.append({'path': str(folder), 'reason': str(exc)[:500]})
    return files, issues, limited


def probe_engine(service_name=None):
    engine = ClamAVScanner(service_name=service_name, require_verified_peer=os.name == 'nt')
    try:
        return dict(engine.metadata, available=True)
    finally:
        engine.close()


class Guard:
    def __init__(self, policy, state_dir=None, *, scanner=None,
                 probe=None, quarantine_factory=Quarantine, watcher_factory=None):
        self.policy = policy
        self.roots = policy.validate()
        self.state_dir = Path(state_dir or default_guard_path()).absolute()
        self.excluded = (self.state_dir, default_quarantine_path().absolute())
        for excluded in self.excluded:
            if any(root == excluded or excluded in root.parents for root in self.roots):
                raise ValueError('A watched root cannot be inside Guard state or quarantine storage')
        if scanner is None:
            self.scanner = lambda path, **kwargs: run_scan_process(
                path, engine_service=policy.engine_service,
                require_verified_peer=os.name == 'nt', **kwargs)
        else:
            self.scanner = scanner
        self.probe = (lambda: probe_engine(policy.engine_service)) if probe is None else probe
        self.quarantine_factory = quarantine_factory
        self.watcher_factory = watcher_factory or (DirectoryNotifications if os.name == 'nt' else PollNotifications)
        self.pending = OrderedDict()
        self.queue_cursor = None
        self.known, self.failures, self.threats = {}, {}, {}
        self.status = {'schema': 1, 'kind': 'antivirus-guard', 'run_id': uuid.uuid4().hex,
                       'state': 'starting', 'running': True, 'pid': os.getpid(),
                       'started_at': time.time(), 'heartbeat': time.time(),
                       'roots': [str(root) for root in self.roots],
                       'mode': 'quarantine' if policy.auto_quarantine else 'notify',
                       'pre_execution_blocking': False, 'coverage': 'selected-directories-after-change',
                       'engine': {}, 'scanned': 0, 'detections': 0, 'quarantined': 0,
                       'errors': 0, 'pending': 0, 'unresolved': 0, 'inventory_issues': [],
                       'capacity_exceeded': False, 'notifications': 'starting',
                       'notification_resyncs': 0}

    def invalidate_changes(self, batch):
        # Events identify work; only inventory may admit files to the scan queue.
        # Prefix matching also covers directory moves and renames. The set bounds
        # this to O(cached paths * path depth), not O(paths * notification count).
        affected = {path for path in (*batch.paths, *batch.reset_roots)
                    if any(path == root or root in path.parents for root in self.roots)
                    and not any(path == root or root in path.parents for root in self.excluded)}
        if not affected:
            return False
        def matches(path):
            return path in affected or not affected.isdisjoint(path.parents)
        for path in list(self.known):
            if matches(path):
                del self.known[path]
        ready_at = time.monotonic() + self.policy.settle
        for path, (identity, _) in list(self.pending.items()):
            if matches(path):
                self.pending[path] = (identity, ready_at)
        return True

    def run(self, stop=None):
        stop = stop or threading.Event()
        store = GuardState(self.state_dir)
        try:
            store.acquire()
        except BaseException:
            store.close()
            raise
        watcher = None
        last_heartbeat, last_probe, last_inventory = 0.0, float('-inf'), float('-inf')
        version, changed, notification_error = None, True, False
        next_notification_retry = 0.0

        def cancelled():
            nonlocal last_heartbeat
            now = time.monotonic()
            if now - last_heartbeat >= 0.5:
                last_heartbeat = now
                self.status.update(heartbeat=time.time(), pending=len(self.pending),
                                   unresolved=len(self.failures), active_threats=len(self.threats))
                store.publish(self.status)
                if store.stopped(self.status['run_id']):
                    stop.set()
            return stop.is_set()

        store.publish(self.status)
        store.event('started', {'roots': self.status['roots'], 'mode': self.status['mode']})
        try:
            while not cancelled():
                now = time.monotonic()
                if watcher is None and now >= next_notification_retry:
                    next_notification_retry = now + 30
                    try:
                        watcher = self.watcher_factory(self.roots)
                        notification_error = False
                        self.status['notifications'] = 'native' if watcher.native else 'periodic'
                        # Changes while the notification handle was unavailable
                        # may have preserved every cached metadata field.
                        self.invalidate_changes(ChangeBatch(reset_roots=self.roots))
                        last_inventory = float('-inf')
                    except OSError as exc:
                        notification_error = True
                        self.status['notifications'] = 'failed; periodic reconciliation continues'
                        store.event('notification-error', {'error': str(exc)[:500]})
                if now - last_probe >= 30:
                    last_probe = now
                    try:
                        metadata = self.probe()
                        if metadata.get('version') != version:
                            version = metadata.get('version')
                            self.known.clear()
                            changed = True
                        if metadata != self.status['engine']:
                            store.event('engine', metadata)
                        self.status['engine'] = metadata
                    except (OSError, RuntimeError) as exc:
                        self.status['engine'] = {'available': False, 'detail': str(exc)[:500]}
                        store.event('engine-error', self.status['engine'])
                if now - last_inventory >= self.policy.interval:
                    last_inventory = now
                    files, issues, limited = inventory(self.roots, max_files=self.policy.max_files,
                        excluded=self.excluded, cancelled=cancelled)
                    self.status['inventory_issues'] = issues
                    self.status['capacity_exceeded'] = limited
                    for mapping in (self.pending, self.known, self.failures, self.threats):
                        for path in list(mapping):
                            if path not in files and not limited and not issues:
                                del mapping[path]
                    # Refresh every admitted file even if a full queue stops
                    # admission before that path's position in the inventory.
                    for path, (identity, _) in list(self.pending.items()):
                        current = files.get(path)
                        if current is not None and current != identity:
                            self.pending[path] = (current, now + self.policy.settle)
                    # Continue after the last admission. Repeated writes/cache
                    # resets in the first entries must not starve the backlog.
                    entries = list(files.items())
                    start = next((index + 1 for index, (path, _) in enumerate(entries)
                                  if path == self.queue_cursor), 0)
                    for offset in range(len(entries)):
                        path, identity = entries[(start + offset) % len(entries)]
                        known = self.known.get(path)
                        if known and known[0] == identity and now - known[1] < known[2]:
                            continue
                        pending = self.pending.get(path)
                        if pending is not None:
                            continue
                        if len(self.pending) >= self.policy.max_queue:
                            self.status['capacity_exceeded'] = True
                            break
                        self.pending[path] = (identity, now + self.policy.settle)
                        self.queue_cursor = path
                    changed = False
                ready = next(((path, item) for path, item in self.pending.items()
                              if now >= item[1]), None)
                if ready and self.status['engine'].get('available') and not cancelled():
                    path, (identity, _) = ready
                    del self.pending[path]
                    self.status.update(state='scanning', current_path=str(path))
                    store.publish(self.status)
                    try:
                        result = self.scanner(path, engine='clamav', timeout=45, cancelled=cancelled)
                        if cancelled():
                            break
                        self.status['scanned'] += result['summary']['files_scanned']
                        if not result['engine'].get('available') or result['engine'].get('failed_during_scan'):
                            self.status['engine'] = dict(result['engine'], available=False)
                            last_probe = time.monotonic()
                        incomplete = result['coverage'] == 'limited'
                        if incomplete:
                            self.failures[path] = 'incomplete scan'
                        else:
                            self.failures.pop(path, None)
                        findings = result['findings']
                        if findings or incomplete:
                            store.event('scan', {'path': str(path), 'verdict': result['verdict'],
                                'coverage': result['coverage'], 'findings': findings,
                                'issues': result['issues'], 'engine': result['engine']})
                        for finding in findings:
                            if finding['kind'] != 'threat':
                                continue
                            self.threats[path] = finding['name']
                            self.status['detections'] += 1
                            if self.policy.auto_quarantine:
                                item = self.quarantine_factory().add(finding, dry_run=False)
                                store.event('quarantined', {'path': str(path), 'id': item['id'], 'name': finding['name']})
                                self.status['quarantined'] += 1
                                self.threats.pop(path, None)
                                self.failures.pop(path, None)
                        try:
                            current = file_identity(checked_path(path).stat())
                        except FileNotFoundError:
                            current = None
                        # A scan result never covers bytes written during detection.
                        if current == identity:
                            if not incomplete and not any(f['kind'] == 'threat' for f in findings):
                                self.threats.pop(path, None)
                            if len(self.known) >= self.policy.max_files and path not in self.known:
                                self.known.pop(next(iter(self.known)))
                            self.known[path] = (identity, time.monotonic(), 30 if incomplete else self.policy.rescan)
                    except (OSError, RuntimeError, ValueError) as exc:
                        self.status['errors'] += 1
                        self.failures[path] = str(exc)[:500]
                        if len(self.known) >= self.policy.max_files and path not in self.known:
                            self.known.pop(next(iter(self.known)))
                        self.known[path] = (identity, time.monotonic(), 30)
                        store.event('scan-error', {'path': str(path), 'error': str(exc)[:500]})
                    self.status.pop('current_path', None)
                if len(self.failures) > self.policy.max_files or len(self.threats) > self.policy.max_files:
                    raise RuntimeError('Guard incident capacity exceeded; review history and reduce watched scope')
                degraded = (notification_error or self.failures or self.status['inventory_issues'] or
                            self.status['capacity_exceeded'] or not self.status['engine'].get('available') or
                            self.status['engine'].get('database_freshness') != 'current')
                self.status['state'] = 'degraded' if degraded else 'attention' if self.threats else 'monitoring'
                if watcher is not None:
                    try:
                        batch = watcher.wait(0.05 if ready else 0.25)
                        changed = self.invalidate_changes(batch) or changed
                        if batch.reset_roots:
                            self.status['notification_resyncs'] += 1
                            store.event('notification-resync', {'roots': [str(p) for p in batch.reset_roots]})
                        # A timed sweep remains even when no event was received.
                        if changed and time.monotonic() - last_inventory >= 0.5:
                            last_inventory = float('-inf')
                    except OSError as exc:
                        watcher.close()
                        watcher = None
                        notification_error = True
                        self.status['notifications'] = 'failed; periodic reconciliation continues'
                        self.invalidate_changes(ChangeBatch(reset_roots=self.roots))
                        last_inventory = float('-inf')
                        store.event('notification-error', {'error': str(exc)[:500]})
                else:
                    stop.wait(0.25)
        except KeyboardInterrupt:
            stop.set()
            raise
        except BaseException as exc:
            self.status.update(state='failed', last_error=str(exc)[:500])
            raise
        finally:
            if watcher is not None:
                watcher.close()
            self.status.update(running=False, heartbeat=time.time(), pending=len(self.pending),
                               unresolved=len(self.failures), active_threats=len(self.threats))
            if self.status['state'] != 'failed':
                self.status['state'] = 'stopped'
            try:
                store.publish(self.status)
                store.event('stopped', {'state': self.status['state']})
            finally:
                store.close()
        return self.status


def load_policy(path):
    from .antivirus import read_regular
    content, _ = read_regular(Path(path), 65536)
    data = json.loads(content)
    if not isinstance(data, dict) or data.get('schema') != 1:
        raise ValueError('Guard policy must use schema 1')
    if set(data) - {'schema', 'roots', 'auto_quarantine', 'engine_service'}:
        raise ValueError('Unknown guard policy field')
    roots = data.get('roots')
    if not isinstance(roots, list) or not all(isinstance(p, str) for p in roots):
        raise ValueError('Guard roots must be a list of paths')
    if any(not Path(p).is_absolute() for p in roots):
        raise ValueError('Policy roots must be absolute paths')
    automatic = data.get('auto_quarantine', False)
    if not isinstance(automatic, bool):
        raise ValueError('auto_quarantine must be boolean')
    engine_service = data.get('engine_service')
    if engine_service is not None and not isinstance(engine_service, str):
        raise ValueError('engine_service must be a service name string')
    if engine_service is not None:
        from .windows_clamd_peer import validate_service_name
        validate_service_name(engine_service)
    return GuardPolicy(tuple(Path(p) for p in roots), auto_quarantine=automatic,
                       engine_service=engine_service)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='antios guard', description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('roots', nargs='*', type=Path)
    run.add_argument('--policy', type=Path)
    run.add_argument('--auto-quarantine', action='store_true', help='Explicitly permit automatic encrypted isolation of confirmed detections.')
    run.add_argument('--engine-service', help='Windows SCM service name owning the trusted ClamD process.')
    run.add_argument('--state-dir', type=Path)
    for name in ('status', 'stop', 'history'):
        commands.add_parser(name).add_argument('--state-dir', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command != 'run':
            status = read_guard_state(args.state_dir, history=args.command == 'history', stop=args.command == 'stop')
            print(json.dumps(status, indent=2, ensure_ascii=False))
            return 0
        if args.policy:
            if args.roots or args.auto_quarantine or args.engine_service:
                raise ValueError('Use a policy file or inline roots/options, not both')
            policy = load_policy(args.policy)
        else:
            policy = GuardPolicy(tuple(args.roots), auto_quarantine=args.auto_quarantine,
                                 engine_service=args.engine_service)
        if policy.auto_quarantine and os.name != 'nt':
            raise ValueError('Automatic encrypted quarantine requires Windows DPAPI')
        print('AntiOS Guard: post-write detection for selected directories; pre-execution blocking is unavailable.', flush=True)
        Guard(policy, args.state_dir).run()
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f'AntiOS Guard: {exc}', file=sys.stderr)
        return 2


def launch_guard(root):
    """Explicit GUI action; the companion outlives the dashboard until stopped."""
    import subprocess
    import sys
    path = GuardPolicy((Path(root),)).validate()[0]
    if read_guard_state().get('running'):
        raise RuntimeError('AntiOS Guard is already running; stop it before changing roots')
    if getattr(sys, 'frozen', False):
        executable = Path(sys.executable).parent / 'AntiOS-Guard.exe'
        if not executable.is_file():
            raise FileNotFoundError('AntiOS-Guard.exe is missing from the portable installation')
        command = [str(executable), 'run', str(path)]
    else:
        command = [sys.executable, '-m', 'antios.guard', 'run', str(path)]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return {'pid': process.pid, 'root': str(path)}


if __name__ == '__main__':
    raise SystemExit(main())
