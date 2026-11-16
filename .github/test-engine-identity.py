#!/usr/bin/env python3
"""Build-guard fixtures use the real engine files and real Git snapshots.

Fixture metadata exercises refusal rules; production uses the actual retained
Cargo metadata, not these fixture objects. This creates no domain authority.
"""
import copy
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from engine_identity import verified_engine_pair, ENGINE_SOURCE, KEYS_SOURCE

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('check-first-party.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class Fixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.workspace, self.selected = base / 'workspace', base / 'selected'
        original = Path(__file__).resolve().parent.parent
        self.workspace.mkdir()
        self.selected.mkdir()
        for root in [self.workspace, self.selected]:
            shutil.copytree(original / 'engine', root / 'engine')
        shutil.copyfile(original / 'Cargo.toml', self.workspace / 'Cargo.toml')
        self.git('init', '-q')
        self.git('add', '--', 'engine')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Original engine fixture')
        self.revision = self.git('rev-parse', 'HEAD').decode().strip()
        self.source = ENGINE_SOURCE + self.revision
        self.metadata = {
            'version': 1, 'workspace_root': str(self.workspace),
            'workspace_members': ['app', 'local'],
            'packages': [
                {'id': 'local', 'name': 'cwlt-engine', 'version': '0.0.0', 'source': None, 'manifest_path': str(self.workspace / 'engine/Cargo.toml')},
                {'id': 'selected', 'name': 'cwlt-engine', 'version': '0.0.0', 'source': self.source, 'manifest_path': str(self.selected / 'engine/Cargo.toml')},
                {'id': 'app', 'name': 'cwlt', 'version': '0.0.0', 'source': None, 'manifest_path': str(self.workspace / 'Cargo.toml')},
                {'id': 'keys', 'name': 'ckmg', 'version': '0.0.0', 'source': KEYS_SOURCE + 'a' * 40},
            ],
            'resolve': {'nodes': [
                {'id': 'app', 'features': ['record'], 'deps': [self.edge('ckmg', 'keys')]},
                {'id': 'keys', 'features': ['wallet-engine'], 'deps': [self.edge('cwlt_engine', 'selected')]},
                {'id': 'local', 'features': [], 'deps': []},
                {'id': 'selected', 'features': [], 'deps': []},
            ]},
        }

    @staticmethod
    def edge(name, package):
        return {'name': name, 'pkg': package, 'dep_kinds': [{'kind': None, 'target': None}]}

    def git(self, *arguments):
        return subprocess.check_output(['git', '-C', str(self.selected), *arguments], stderr=subprocess.PIPE)

    def pair(self, metadata=None):
        return verified_engine_pair(metadata or self.metadata, self.workspace)


class EngineIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.temporary.cleanup)

    def test_exact_real_git_sources_and_graph_only_allow_exact_lock_pair(self):
        pair = self.fixture.pair()
        local = {'name': 'cwlt-engine', 'version': '0.0.0'}
        selected = dict(local, source=self.fixture.source)
        guard.check_lock([local, selected], pair)
        with self.assertRaises(ValueError):
            guard.check_lock([local, selected])
        changed = self.fixture.source[:-1] + ('b' if self.fixture.source[-1] != 'b' else 'a')
        for packages in [[local, selected, selected], [local, dict(selected, version='0.0.1')],
                         [local, dict(selected, source=changed)], [dict(local, source=''), selected]]:
            with self.assertRaises(ValueError):
                guard.check_lock(packages, pair)

    def test_third_source_branch_version_path_and_membership_drift_refuse(self):
        for case in range(7):
            metadata = copy.deepcopy(self.fixture.metadata)
            selected = metadata['packages'][1]
            if case == 0:
                extra = dict(selected, id='third')
                metadata['packages'].append(extra)
            elif case == 1:
                selected['source'] = selected['source'].replace('/cwlt.git?', '/cwlt?')
            elif case == 2:
                selected['source'] = selected['source'].replace('branch=main', 'branch=v01')
            elif case == 3:
                selected['version'] = '0.0.1'
            elif case == 4:
                metadata['packages'][0]['manifest_path'] = str(self.fixture.selected / 'engine/Cargo.toml')
            elif case == 5:
                metadata['workspace_members'].append('selected')
            elif case == 6:
                selected['source'] = ENGINE_SOURCE + 'b' * 40
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.fixture.pair(metadata)

    def test_local_or_selected_bytes_extra_files_and_symlinks_refuse(self):
        for root in [self.fixture.workspace, self.fixture.selected]:
            file = root / 'engine/src/lib.rs'
            original = file.read_bytes()
            file.write_bytes(original + b'\n// changed source\n')
            with self.assertRaises(ValueError):
                self.fixture.pair()
            file.write_bytes(original)
        extra = self.fixture.workspace / 'engine/src/extra.rs'
        extra.write_text('// additional source\n')
        with self.assertRaises(ValueError):
            self.fixture.pair()
        extra.unlink()
        file = self.fixture.workspace / 'engine/src/lib.rs'
        file.unlink()
        file.symlink_to(self.fixture.selected / 'engine/src/lib.rs')
        with self.assertRaises(ValueError):
            self.fixture.pair()

    def test_production_root_keys_engine_graph_refuses_local_or_unverified_edges(self):
        for case in range(5):
            metadata = copy.deepcopy(self.fixture.metadata)
            app, keys = metadata['resolve']['nodes'][:2]
            if case == 0:
                keys['deps'][0]['pkg'] = 'local'
            elif case == 1:
                app['deps'].append(self.fixture.edge('direct_engine', 'local'))
            elif case == 2:
                keys['deps'][0]['dep_kinds'][0]['kind'] = 'dev'
            elif case == 3:
                app['features'] = []
            elif case == 4:
                app['deps'].append(self.fixture.edge('unknown', 'missing'))
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.fixture.pair(metadata)


if __name__ == '__main__':
    unittest.main()
