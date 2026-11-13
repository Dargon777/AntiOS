"""Inspect the built PE resources and exercise the actual frozen scan worker."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import pefile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    '--rust-dll', type=Path,
    help='Require the three packaged DLLs and check that the frozen workers use Rust',
)
rust_dll = parser.parse_args().rust_dll
runtime_dirs = {'AntiOS': '_cli', 'AntiOS-GUI': '_gui', 'AntiOS-Guard': '_guard'}

for name, runtime_dir in runtime_dirs.items():
    executable = Path('dist') / name / (name + '.exe')
    if rust_dll:
        native_dir = executable.parent / runtime_dir / 'antios' / '_native'
        packaged_dll = native_dir / 'antios_static_core.dll'
        assert packaged_dll.read_bytes() == rust_dll.read_bytes(), packaged_dll
        assert (native_dir / 'licenses' / 'CONTENTS.txt').is_file(), native_dir
    pe = pefile.PE(str(executable))
    values = {}
    for group in pe.FileInfo:
        for item in group:
            for table in getattr(item, 'StringTable', []):
                values.update(table.entries)
    assert values[b'CompanyName'] == b'DargonITP', values
    manifests = []
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 24:
            for item in entry.directory.entries:
                for language in item.directory.entries:
                    data = language.data.struct
                    manifests.append(ET.fromstring(pe.get_data(data.OffsetToData, data.Size)))
    levels = [level.attrib['level'] for root in manifests
              for level in root.iter('{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')]
    expected_level = 'requireAdministrator' if name == 'AntiOS' else 'asInvoker'
    assert levels == [expected_level], levels
    pe.close()
    with tempfile.TemporaryDirectory() as folder:
        workspace = Path(folder)
        request, events = workspace / 'request.json', workspace / 'events.jsonl'
        sample = Path('release/VERSION').resolve()
        if rust_dll:
            sample = workspace / 'truncated.exe'
            sample.write_bytes(b'MZ')
        request.write_text(json.dumps({'path': str(sample), 'use_cache': False}), encoding='utf-8')
        subprocess.run([str(executable.resolve()), '--antios-scan-worker', str(request), str(events)],
                       timeout=60, check=True)
        records = [json.loads(line) for line in events.read_text(encoding='utf-8').splitlines()]
        assert records[-1][0] == 'done', records
        checkpoints = [value for kind, value in records if kind == 'checkpoint']
        result = checkpoints[-1]
        assert result['summary']['files_scanned'] == 1, result
        assert result['summary']['threats'] == 0, result
        if rust_dll:
            assert result['engine']['static_core'] == 'rust', result
            finding, = (item for checkpoint in checkpoints for item in checkpoint['findings'])
            assert finding['kind'] == 'review', finding
            assert 'invalid-pe-header' in finding['coverage_gaps'], finding
            assert finding['sha256'] == hashlib.sha256(b'MZ').hexdigest(), finding
    print(f'{name}: DargonITP metadata, {expected_level} manifest, frozen worker OK')
