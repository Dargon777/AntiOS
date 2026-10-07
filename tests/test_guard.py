import errno
import json
from pathlib import Path
import queue
import threading
import time

import pytest

from antios import guard
from antios.antivirus import scan_files
from antios.behavior import BehaviorEngine, ProcessEvent
from antios.clamav import ScanOutcome
from antios.guard_notifications import ChangeBatch, PollNotifications
from antios.guard_state import GuardState, read_guard_state


class Engine:
    metadata = {'version': 'test-generation', 'database_freshness': 'current'}
    def scan(self, data, name):
        return ScanOutcome('threat', 'Inert.Test') if b'inert-marker' in data else ScanOutcome()
    def close(self):
        pass


def scan(path, **options):
    return scan_files(path, engine='clamav', provider_factory=Engine, cancelled=options['cancelled'])


def probe():
    return dict(Engine.metadata, available=True)


def until(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail('guard did not reach expected state')
        time.sleep(0.02)


def launch(tmp_path, **options):
    root = tmp_path / 'watched'
    root.mkdir(exist_ok=True)
    state = tmp_path / 'state'
    policy = guard.GuardPolicy((root,), interval=0.1, settle=0.05,
                                auto_quarantine=options.pop('auto_quarantine', False),
                                max_queue=options.pop('max_queue', 256))
    instance = guard.Guard(policy, state, scanner=options.pop('scanner', scan), probe=options.pop('probe', probe),
                           watcher_factory=options.pop('watcher_factory', PollNotifications), **options)
    stop, failures = threading.Event(), []
    def run():
        try:
            instance.run(stop)
        except Exception as exc:
            failures.append(exc)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return root, state, instance, stop, thread, failures


def test_existing_new_and_modified_files_are_scanned_once_until_changed(tmp_path):
    root = tmp_path / 'watched'
    root.mkdir()
    existing = root / 'existing'
    existing.write_bytes(b'ordinary')
    root, state, instance, stop, thread, failures = launch(tmp_path)
    try:
        until(lambda: instance.status['scanned'] >= 1)
        first = instance.status['scanned']
        time.sleep(0.3)
        assert instance.status['scanned'] == first
        new = root / 'new'
        new.write_bytes(b'inert-marker')
        until(lambda: instance.status['detections'] == 1)
        existing.write_bytes(b'inert-marker changed')
        until(lambda: instance.status['detections'] == 2)
        assert existing.exists() and new.exists()  # notify is the default
        until(lambda: read_guard_state(state).get('detections') == 2)
        status = read_guard_state(state, history=True, stop=True)
        assert not status['pre_execution_blocking']
        assert status['stop_requested']
        thread.join(3)
        assert not thread.is_alive()
        assert read_guard_state(state)['state'] == 'stopped'
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_automatic_quarantine_is_explicit_and_never_acts_on_reviews(tmp_path):
    isolated = []
    class Vault:
        def add(self, finding, *, dry_run):
            assert dry_run is False
            isolated.append(finding)
            Path(finding['path']).unlink()
            return {'id': 'test-backup'}
    root, state, instance, stop, thread, failures = launch(tmp_path, auto_quarantine=True, quarantine_factory=Vault)
    try:
        # Avoid racing file creation against Guard's initial engine probe on
        # slow/shared Windows CI runners.
        until(lambda: instance.status['state'] == 'monitoring')
        target = root / 'fixture'
        target.write_bytes(b'inert-marker')
        until(lambda: instance.status['quarantined'] == 1)
        assert len(isolated) == 1
        assert not target.exists()
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_failed_engine_keeps_pending_work_and_reports_degraded(tmp_path):
    def broken():
        raise OSError('offline')
    root, state, instance, stop, thread, failures = launch(tmp_path, probe=broken, max_queue=2)
    try:
        for index in range(5):
            (root / str(index)).write_text('ordinary')
        until(lambda: instance.status['capacity_exceeded'])
        until(lambda: read_guard_state(state).get('state') == 'degraded')
        assert len(instance.pending) == 2
        assert instance.status['scanned'] == 0
        assert read_guard_state(state)['engine']['available'] is False
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_engine_version_change_invalidates_cached_results(tmp_path, monkeypatch):
    # Directly exercise a short clock jump instead of waiting 30 seconds.
    clock = [100.0]
    monkeypatch.setattr(guard.time, 'monotonic', lambda: clock[0])
    generation = ['first']
    def changing_probe():
        return dict(probe(), version=generation[0])
    root, state, instance, stop, thread, failures = launch(tmp_path, probe=changing_probe)
    try:
        (root / 'ordinary').write_bytes(b'ordinary')
        for _ in range(100):
            clock[0] += 0.2
            if instance.status['scanned']:
                break
            time.sleep(0.02)
        assert instance.status['scanned'] == 1
        generation[0] = 'second'
        clock[0] += 31
        for _ in range(100):
            clock[0] += 0.2
            if instance.status['scanned'] == 2:
                break
            time.sleep(0.02)
        assert instance.status['scanned'] == 2
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_changed_during_scan_is_not_cached_as_checked(tmp_path):
    calls = []
    def changing_scan(path, **options):
        result = scan(path, **options)
        calls.append(path)
        if len(calls) == 1:
            path.write_bytes(b'inert-marker changed during detection')
        return result
    root, state, instance, stop, thread, failures = launch(tmp_path, scanner=changing_scan)
    try:
        (root / 'fixture').write_text('ordinary')
        until(lambda: instance.status['detections'] == 1)
        assert len(calls) >= 2
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_inventory_skips_links_vault_and_limits_directory_growth(tmp_path):
    vault = tmp_path / 'vault'
    vault.mkdir()
    (vault / 'item').write_text('excluded')
    (tmp_path / 'ordinary').write_text('ordinary')
    for index in range(10):
        (tmp_path / f'dir-{index}').mkdir()
    files, issues, limited = guard.inventory((tmp_path,), excluded=(vault,), max_files=2)
    assert limited
    assert all(vault not in path.parents for path in files)


def test_journal_has_exclusive_owner_bounded_history_and_stale_status(tmp_path):
    state = GuardState(tmp_path / 'state')
    other = GuardState(tmp_path / 'state')
    try:
        state.acquire()
        with pytest.raises(OSError, match='already running'):
            other.acquire()
        for number in range(1005):
            state.event('test', {'number': number})
        assert state.db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1000
        state.publish({'state': 'monitoring', 'running': True, 'heartbeat': time.time()-100, 'run_id': 'old'})
        assert read_guard_state(state.folder)['state'] == 'unresponsive'
        assert not read_guard_state(state.folder, stop=True).get('stop_requested')
    finally:
        other.close()
        state.close()


def test_policy_rejects_ambiguous_boolean_and_unknown_keys(tmp_path):
    policy = tmp_path / 'policy.json'
    for data in ({'schema': 1, 'roots': [str(tmp_path)], 'auto_quarantine': 'false'},
                 {'schema': 1, 'roots': [str(tmp_path)], 'disable_defender': True}):
        policy.write_text(json.dumps(data))
        with pytest.raises(ValueError):
            guard.load_policy(policy)
    policy.write_text(json.dumps({'schema': 1, 'roots': [str(tmp_path)]}))
    assert guard.load_policy(policy).auto_quarantine is False


def test_cli_status_is_available_without_windows_or_a_running_guard(tmp_path, capsys):
    from antios.cli import main
    assert main(['guard', 'status', '--state-dir', str(tmp_path / 'missing')]) == 0
    assert json.loads(capsys.readouterr().out)['state'] == 'not-running'


def test_reviews_never_enter_automatic_quarantine(tmp_path):
    calls = []
    class ReviewEngine(Engine):
        def scan(self, data, name):
            return ScanOutcome('review', 'Heuristics.Encrypted.Zip')
    def review_scan(path, **options):
        return scan_files(path, engine='clamav', provider_factory=ReviewEngine)
    class Vault:
        def add(self, *args, **kwargs):
            calls.append(args)
            raise AssertionError('Review must not be quarantined')
    root, state, instance, stop, thread, failures = launch(tmp_path, auto_quarantine=True,
                                                        scanner=review_scan, quarantine_factory=Vault)
    try:
        target = root / 'review'
        target.write_text('ordinary')
        # Hosted Windows runners can take longer to schedule the Guard
        # thread under a full matrix load; keep the same assertion with a
        # slightly wider bounded startup window.
        until(lambda: instance.status['scanned'] == 1, seconds=10)
        until(lambda: instance.status['state'] == 'degraded', seconds=10)
        assert target.exists()
        assert not calls
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_restart_ignores_stop_request_for_old_run(tmp_path):
    root, state, instance, stop, thread, failures = launch(tmp_path)
    try:
        (root / 'fixture').write_text('ordinary')
        until(lambda: instance.status['scanned'] == 1)
        until(lambda: read_guard_state(state).get('running'))
        first_id = read_guard_state(state, stop=True)['run_id']
        thread.join(3)
        assert not thread.is_alive()
    finally:
        stop.set()
        thread.join(3)
    assert not failures
    root, state, instance, stop, thread, failures = launch(tmp_path)
    try:
        until(lambda: instance.status['scanned'] == 1)
        assert instance.status['run_id'] != first_id
        assert thread.is_alive()
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_local_links_are_never_followed_by_inventory(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'not-watched').write_text('ordinary')
    root = tmp_path / 'watched'
    root.mkdir()
    try:
        (root / 'link').symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Symlink privilege unavailable')
    files, issues, _ = guard.inventory((root,))
    assert not files
    assert issues[0]['reason'] == 'link-or-reparse-point'


def test_watch_root_cannot_be_hidden_by_state_exclusion(tmp_path):
    with pytest.raises(ValueError, match='storage'):
        guard.Guard(guard.GuardPolicy((tmp_path,)), tmp_path)


def test_invalid_status_cannot_report_monitoring(tmp_path):
    store = GuardState(tmp_path)
    try:
        store.publish({'state': 'monitoring', 'running': True, 'heartbeat': 'invalid'})
        with pytest.raises(ValueError, match='heartbeat'):
            read_guard_state(tmp_path)
    finally:
        store.close()


class Notifications:
    native = True

    def __init__(self):
        self.events = queue.Queue()

    def wait(self, seconds):
        try:
            item = self.events.get(timeout=seconds)
        except queue.Empty:
            return ChangeBatch()
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        pass


def test_notification_rechecks_unchanged_metadata_without_rescanning_unrelated_files(tmp_path, monkeypatch):
    # Model the Windows case: size, ID, mtime and creation time are unchanged.
    monkeypatch.setattr(guard, 'file_identity', lambda info: (info.st_dev, info.st_ino, info.st_size))
    watcher = Notifications()
    root, state, instance, stop, thread, failures = launch(tmp_path, watcher_factory=lambda roots: watcher)
    try:
        target = root / 'fixture'
        other = root / 'untouched'
        target.write_bytes(b'ordinary----')
        other.write_bytes(b'ordinary----')
        until(lambda: len(instance.known) == 2)
        first = instance.status['scanned']
        target.write_bytes(b'inert-marker')
        watcher.events.put(ChangeBatch(paths=(target,)))
        until(lambda: instance.status['detections'] == 1)
        assert instance.status['scanned'] == first + 1
        # A subsequently verified benign replacement clears the active alert,
        # while the historical detection remains in the journal and counters.
        target.write_bytes(b'ordinary----')
        watcher.events.put(ChangeBatch(paths=(target,)))
        until(lambda: not instance.threats)
        assert instance.status['detections'] == 1
    finally:
        stop.set()
        thread.join(3)
    assert not failures


@pytest.mark.parametrize('lost_event', ['overflow', 'watcher-error'])
def test_lost_events_invalidate_old_results_even_when_metadata_matches(tmp_path, monkeypatch, lost_event):
    monkeypatch.setattr(guard, 'file_identity', lambda info: (info.st_dev, info.st_ino, info.st_size))
    watcher = Notifications()
    root, state, instance, stop, thread, failures = launch(tmp_path, watcher_factory=lambda roots: watcher)
    try:
        target = root / 'fixture'
        target.write_bytes(b'ordinary----')
        until(lambda: target in instance.known)
        target.write_bytes(b'inert-marker')
        watcher.events.put(ChangeBatch(reset_roots=(root,)) if lost_event == 'overflow' else OSError('lost handle'))
        until(lambda: instance.status['detections'] == 1)
        if lost_event == 'overflow':
            assert instance.status['notification_resyncs'] == 1
        else:
            until(lambda: instance.status['state'] == 'degraded')
            assert instance.status['notifications'].startswith('failed')
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_notification_during_scan_invalidates_just_computed_result(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'file_identity', lambda info: (info.st_dev, info.st_ino, info.st_size))
    watcher = Notifications()
    calls = []
    def changing_scan(path, **options):
        result = scan(path, **options)
        calls.append(path)
        if len(calls) == 1:
            path.write_bytes(b'inert-marker')
            watcher.events.put(ChangeBatch(paths=(path,)))
        return result
    root, state, instance, stop, thread, failures = launch(tmp_path, scanner=changing_scan,
                                                        watcher_factory=lambda roots: watcher)
    try:
        (root / 'fixture').write_bytes(b'ordinary----')
        until(lambda: instance.status['detections'] == 1)
        assert len(calls) >= 2
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_subtree_events_reset_descendants_but_exclude_guard_storage(tmp_path):
    root = tmp_path / 'watched'
    root.mkdir()
    state = root / 'guard-state'
    instance = guard.Guard(guard.GuardPolicy((root,)), state)
    nested, sibling = root / 'nested' / 'fixture', root / 'sibling'
    instance.known = {nested: ((), 0, 900), sibling: ((), 0, 900)}
    instance.pending[nested] = ((), 0)
    assert not instance.invalidate_changes(ChangeBatch(paths=(state / 'events.db',)))
    assert not instance.invalidate_changes(ChangeBatch(paths=(tmp_path / 'outside',)))
    assert instance.invalidate_changes(ChangeBatch(paths=(nested.parent,)))
    assert nested not in instance.known and sibling in instance.known
    assert instance.pending[nested][1] > time.monotonic()


def test_repeated_root_rescans_do_not_starve_files_beyond_queue_capacity(tmp_path):
    watcher = Notifications()
    visited = set()
    root = tmp_path / 'watched'
    root.mkdir()
    for index in range(6):
        (root / f'file-{index}').write_text('ordinary')
    def busy_scan(path, **options):
        result = scan(path, **options)
        visited.add(path)
        watcher.events.put(ChangeBatch(reset_roots=(root,)))
        return result
    root, state, instance, stop, thread, failures = launch(tmp_path, scanner=busy_scan, max_queue=2,
                                                        watcher_factory=lambda roots: watcher)
    try:
        until(lambda: len(visited) == 6)
        assert len(instance.pending) <= 2
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_inventory_identity_matches_post_scan_stat(tmp_path):
    target = tmp_path / 'stable.txt'
    target.write_bytes(b'ordinary')
    files, issues, limited = guard.inventory((tmp_path,))
    assert not issues and not limited
    assert files[target] == guard.file_identity(target.stat())



def test_guard_policy_accepts_explicit_trusted_engine_service(tmp_path):
    policy = tmp_path / 'policy.json'
    policy.write_text(json.dumps({
        'schema': 1,
        'roots': [str(tmp_path)],
        'engine_service': 'AntiOSClamD',
    }))
    loaded = guard.load_policy(policy)
    assert loaded.engine_service == 'AntiOSClamD'


@pytest.mark.parametrize('value', ['bad service', '../clamd', '', 123])
def test_guard_policy_rejects_invalid_engine_service(tmp_path, value):
    policy = tmp_path / 'policy.json'
    policy.write_text(json.dumps({
        'schema': 1,
        'roots': [str(tmp_path)],
        'engine_service': value,
    }))
    with pytest.raises(ValueError):
        guard.load_policy(policy)


def test_high_risk_extensions_use_fast_settle(tmp_path):
    root = tmp_path / 'watched-fast-path'
    root.mkdir()
    instance = guard.Guard(
        guard.GuardPolicy((root,), settle=1.0),
        tmp_path / 'guard-fast-state',
        scanner=scan,
        probe=probe,
        watcher_factory=PollNotifications,
    )
    assert instance._settle_delay(root / 'payload.exe') == pytest.approx(0.20)
    assert instance._settle_delay(root / 'script.ps1') == pytest.approx(0.20)
    assert instance._settle_delay(root / 'document.txt') == pytest.approx(1.0)


def test_fast_path_never_claims_pre_execution_blocking(tmp_path):
    root = tmp_path / 'watched-fast-claim'
    root.mkdir()
    instance = guard.Guard(
        guard.GuardPolicy((root,), settle=1.0),
        tmp_path / 'guard-fast-claim-state',
        scanner=scan,
        probe=probe,
        watcher_factory=PollNotifications,
    )
    assert instance.status['fast_path_seconds'] == pytest.approx(0.20)
    assert instance.status['pre_execution_blocking'] is False


def test_transient_scan_conflict_is_deferred_then_recovers(tmp_path):
    calls = []
    def sometimes_busy(path, **options):
        calls.append(path)
        if len(calls) == 1:
            raise OSError(errno.EBUSY, 'temporarily held by another scanner')
        return scan(path, **options)

    root, state, instance, stop, thread, failures = launch(tmp_path, scanner=sometimes_busy)
    try:
        (root / 'sample.exe').write_bytes(b'ordinary')
        until(lambda: instance.status['transient_deferrals'] >= 1)
        until(lambda: instance.status['scanned'] >= 1)
        assert instance.status['errors'] == 0
        assert not instance.failures
        assert len(calls) >= 2
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_transient_scan_conflict_is_bounded(tmp_path):
    def always_busy(path, **options):
        raise OSError(errno.EBUSY, 'still held')

    root, state, instance, stop, thread, failures = launch(tmp_path, scanner=always_busy)
    try:
        target = root / 'locked.exe'
        target.write_bytes(b'ordinary')
        until(lambda: instance.status['errors'] >= 1, seconds=10)
        assert instance.status['transient_deferrals'] == guard._MAX_TRANSIENT_SCAN_RETRIES
        assert target in instance.failures
    finally:
        stop.set()
        thread.join(3)
    assert not failures



def test_guard_journals_behavior_findings_from_process_sampler(tmp_path):
    class Sampler:
        def __init__(self):
            self.sent = False
        def poll(self):
            if self.sent:
                return []
            self.sent = True
            return [ProcessEvent(
                pid=200, ppid=100, image='powershell.exe',
                path=r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                parent_image='WINWORD.EXE',
            )]

    root, state, instance, stop, thread, failures = launch(
        tmp_path, process_sampler=Sampler())
    try:
        until(lambda: instance.status.get('behavior', {}).get('highest_score', 0) >= 85)
        status = read_guard_state(state, history=True)
        assert status['behavior']['mode'] == 'detect-only'
        assert status['behavior']['collector'] == 'injected'
        alerts = [event for event in status['events'] if event['kind'] == 'behavior-alert']
        assert alerts
        assert alerts[0]['data']['rule'] == 'document-spawns-interpreter'
        assert alerts[0]['data']['severity'] == 'high'
        assert instance.status['quarantined'] == 0
    finally:
        stop.set()
        thread.join(3)
    assert not failures



def test_guard_fuses_scan_behavior_origin_and_native_state(tmp_path):
    root = tmp_path / "watched-risk"
    root.mkdir()
    target = root / "payload.exe"
    target.write_bytes(b"ordinary")

    behavior = BehaviorEngine()
    behavior.observe_file_change(str(target))
    behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="payload.exe", path=str(target),
        parent_image="explorer.exe",
    ))

    state = tmp_path / "risk-state"
    policy = guard.GuardPolicy((root,), interval=0.1, settle=0.05)
    instance = guard.Guard(
        policy, state, scanner=scan, probe=probe,
        watcher_factory=PollNotifications,
        behavior_engine=behavior,
        process_sampler=type("SilentSampler", (), {"poll": lambda self: []})(),
        native_probe=lambda: True,
    )
    stop, failures = threading.Event(), []
    thread = threading.Thread(
        target=lambda: instance.run(stop),
        daemon=True,
    )
    # Keep exceptions visible instead of losing them in a raw thread.
    def run_guard():
        try:
            instance.run(stop)
        except Exception as exc:
            failures.append(exc)
    thread = threading.Thread(target=run_guard, daemon=True)
    thread.start()
    try:
        until(lambda: instance.status.get("risk", {}).get("evaluations", 0) >= 1)
        context = instance.status["risk"]["last"]
        assert context["behavior_score"] == 75
        assert "changed-then-executed" in context["behavior_rules"]
        assert context["native_pre_execution"] == "active"
        assert context["automatic_enforcement_eligible"] is False
        assert context["classification"] in {"high", "critical-behavior"}
        history = read_guard_state(state, history=True)
        assert any(event["kind"] == "risk-context" for event in history["events"])
    finally:
        stop.set()
        thread.join(3)
    assert not failures


def test_guard_confirmed_threat_risk_allows_existing_auto_quarantine_only(tmp_path):
    isolated = []
    class Vault:
        def add(self, finding, *, dry_run):
            isolated.append(finding)
            Path(finding["path"]).unlink()
            return {"id": "risk-test"}

    root, state, instance, stop, thread, failures = launch(
        tmp_path,
        auto_quarantine=True,
        quarantine_factory=Vault,
        native_probe=lambda: False,
    )
    try:
        target = root / "confirmed.exe"
        target.write_bytes(b"inert-marker")
        until(lambda: instance.status["quarantined"] == 1)
        context = instance.status["risk"]["last"]
        assert context["confirmed_threat"] is True
        assert context["score"] == 100
        assert context["automatic_enforcement_eligible"] is True
        assert len(isolated) == 1
    finally:
        stop.set()
        thread.join(3)
    assert not failures
