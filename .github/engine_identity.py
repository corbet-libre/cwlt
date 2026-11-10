"""Verify the one workspace/git engine pair from actual Cargo metadata and Git."""
import re
import subprocess
import tomllib
from pathlib import Path

ENGINE_SOURCE = 'git+https://git.corbet.ch/corbet-libre/cwlt?branch=main#'
KEYS_SOURCE = 'git+https://git.corbet.ch/corbet-foss/ckmg.git?branch=main#'
ENGINE_VERSION = '0.0.0'
SHA = re.compile(r'^[0-9a-f]{40}$')


def refuse(message):
    raise ValueError(message)


def selected_revision(source, prefix):
    if not isinstance(source, str) or not source.startswith(prefix):
        refuse('Unexpected engine or Keys source')
    revision = source[len(prefix):]
    if not SHA.fullmatch(revision):
        refuse('Missing exact engine or Keys revision')
    return revision


def git(root, *args):
    try:
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        raise ValueError('Engine source Git verification failed') from error


def source_parity(workspace, manifest, revision):
    selected = manifest.parent.parent.resolve()
    if manifest != selected / 'engine/Cargo.toml':
        refuse('Unexpected selected engine path')
    if git(selected, 'rev-parse', 'HEAD').decode().strip() != revision:
        refuse('Selected engine checkout differs from its exact revision')
    expected = {}
    for record in git(selected, 'ls-tree', '-rz', '--full-tree', revision, 'engine').split(b'\0'):
        if not record:
            continue
        properties, encoded_path = record.split(b'\t', 1)
        mode, kind, _ = properties.split()
        path = Path(encoded_path.decode())
        if mode not in [b'100644', b'100755'] or kind != b'blob' or path.parts[0] != 'engine':
            refuse('Unsupported engine source entry')
        expected[path.relative_to('engine')] = git(selected, 'show', f'{revision}:{path.as_posix()}')
    if not expected or len(expected) > 128:
        refuse('Unexpected engine source inventory')
    for root in [workspace / 'engine', selected / 'engine']:
        files = {}
        for entry in root.rglob('*'):
            if entry.is_symlink():
                refuse('Engine source contains a symlink')
            if entry.is_file():
                relative = entry.relative_to(root)
                if relative not in expected:
                    refuse('Engine source contains an additional file')
                files[relative] = entry.read_bytes()
        if files != expected:
            refuse('Workspace and selected engine sources differ')
    return expected


def verified_engine_pair(metadata, workspace):
    """Return only the exact proven lock tuple; this grants no runtime authority."""
    workspace = Path(workspace).resolve()
    if metadata.get('version') != 1 or Path(metadata['workspace_root']).resolve() != workspace:
        refuse('Cargo metadata belongs to a different workspace')
    packages = metadata['packages']
    by_id = {p['id']: p for p in packages}
    if len(by_id) != len(packages):
        refuse('Duplicate Cargo package IDs')
    engines = [p for p in packages if p['name'] == 'cwlt-engine']
    if len(engines) != 2:
        refuse('Expected exactly two engine packages')
    local = [p for p in engines if p['source'] is None]
    selected = [p for p in engines if p['source'] is not None]
    if len(local) != 1 or len(selected) != 1:
        refuse('Expected one workspace and one selected engine')
    local, selected = local[0], selected[0]
    members = metadata['workspace_members']
    if local['id'] not in members or selected['id'] in members:
        refuse('Unexpected engine workspace membership')
    if local['version'] != ENGINE_VERSION or selected['version'] != ENGINE_VERSION:
        refuse('Unexpected engine version')
    if Path(local['manifest_path']).resolve() != workspace / 'engine/Cargo.toml':
        refuse('Unexpected workspace engine path')
    revision = selected_revision(selected['source'], ENGINE_SOURCE)
    selected_manifest = Path(selected['manifest_path']).resolve()
    if selected_manifest == workspace / 'engine/Cargo.toml':
        refuse('Selected engine is the local workspace engine')
    source_parity(workspace, selected_manifest, revision)
    for manifest in [workspace / 'engine/Cargo.toml', selected_manifest]:
        package = tomllib.loads(manifest.read_text())['package']
        if package['name'] != 'cwlt-engine' or package['version'] != ENGINE_VERSION:
            refuse('Engine manifest differs from Cargo metadata')

    roots = [p for p in packages if p['name'] == 'cwlt' and p['source'] is None]
    keys = [p for p in packages if p['name'] == 'ckmg']
    if len(roots) != 1 or len(keys) != 1:
        refuse('Unexpected application or Keys packages')
    root, keys = roots[0], keys[0]
    if root['id'] not in members or Path(root['manifest_path']).resolve() != workspace / 'Cargo.toml':
        refuse('Unexpected application workspace path')
    selected_revision(keys['source'], KEYS_SOURCE)
    nodes = metadata['resolve']['nodes']
    by_node = {n['id']: n for n in nodes}
    if len(by_node) != len(nodes) or 'record' not in by_node[root['id']]['features']:
        refuse('Production record feature is not resolved')

    def normal(node, name):
        matches = [d for d in by_node[node]['deps'] if d['name'] == name
                   and any(k['kind'] is None for k in d['dep_kinds'])]
        if len(matches) != 1:
            refuse('Expected one normal production engine edge')
        return matches[0]['pkg']

    if normal(root['id'], 'ckmg') != keys['id'] or normal(keys['id'], 'cwlt_engine') != selected['id']:
        refuse('Production does not consume the selected Keys engine')
    pending, seen = [root['id']], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        if current == local['id'] or current not in by_node:
            refuse('Application reaches an unverified or local nominal engine')
        seen.add(current)
        pending.extend(d['pkg'] for d in by_node[current]['deps'])
    return ENGINE_VERSION, selected['source']
