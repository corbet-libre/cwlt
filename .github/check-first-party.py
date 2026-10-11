#!/usr/bin/env python3
"""Require approved owner branches and one resolved revision per first-party crate."""
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIRST_PARTY = re.compile(r"^(?:git\+)?https://git\.corbet\.ch/(?:corbet-(?:foss|libs)|cmtymeet)/")
SHA = re.compile(r"^[0-9a-f]{40}$")
# The original receipt-capable custody owners are intentionally retained on v01.
V01_OWNERS = {
    'https://git.corbet.ch/corbet-foss/ckmg.git': 'ckmg',
    'https://git.corbet.ch/corbet-foss/cwst.git': 'cwst',
}


def owner_branch(repository, package):
    return 'v01' if V01_OWNERS.get(repository) == package else 'main'


def check_lock(packages):
    names = {p['name'] for p in packages if FIRST_PARTY.match(p.get('source', ''))}
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Duplicate first-party crate: {name}')
        source = urlsplit(entries[0]['source'].removeprefix('git+'))
        query = parse_qs(source.query, keep_blank_values=True)
        if not SHA.fullmatch(source.fragment):
            raise ValueError(f'Missing resolved revision for {name}')
        repository = source._replace(query='', fragment='').geturl()
        if query != {'branch': [owner_branch(repository, name)]}:
            raise ValueError(f'Invalid first-party source selector for {name}')


def check_manifest(value, package=None):
    if isinstance(value, dict):
        if FIRST_PARTY.match(value.get('git', '')):
            if value.get('branch') != owner_branch(value['git'], package) or {'rev', 'tag'}.intersection(value):
                raise ValueError('First-party dependency must declare its approved owner branch')
        for name, item in value.items():
            selected = item.get('package', name) if isinstance(item, dict) else None
            check_manifest(item, selected)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


def rejects(function, value):
    try:
        function(value)
    except ValueError:
        return
    raise AssertionError(f'Invalid input accepted: {value!r}')


def self_test():
    repo = 'https://git.corbet.ch/corbet-foss/example'
    source = 'git+' + repo + '?branch=main#' + 'a' * 40
    package = {'name': 'example', 'source': source}
    check_lock([package])
    check_lock([{'name': 'local'}])
    for repository, name in V01_OWNERS.items():
        retained = {'name': name, 'source': 'git+' + repository + '?branch=v01#' + 'a' * 40}
        check_lock([retained])
        declaration = {'git': repository, 'branch': 'v01'}
        check_manifest({'dependencies': {name: declaration}})
        check_manifest({'dependencies': {'alias': dict(declaration, package=name)}})
        rejects(check_manifest, {'dependencies': {'wrong': declaration}})
        rejects(check_lock, [dict(retained, name='wrong')])
        rejects(check_lock, [retained, retained])
        rejects(check_lock, [dict(retained, source=retained['source'].replace('v01', 'other'))])
        rejects(check_manifest, {'dependencies': {name: dict(declaration, rev='a' * 40)}})
        rejects(check_manifest, {'dependencies': {name: dict(declaration, tag='v01')}})
    rejects(check_manifest, {'dependencies': {'example': {'git': repo, 'branch': 'v01'}}})
    rejects(check_lock, [dict(package, source='git+' + repo + '?rev=' + 'a' * 40 + '#' + 'a' * 40)])
    for packages in ([package, package], [package, {'name': 'example'}],
                     [package, dict(package, source=source[:-1] + 'b')],
                     [dict(package, source=source.replace('main', 'develop'))],
                     [dict(package, source=source.replace('branch=main', 'tag=v1'))],
                     [dict(package, source=source.replace('branch=main', 'rev=' + 'b' * 40))],
                     [dict(package, source=source.replace('#' + 'a' * 40, '#short'))],
                     [dict(package, source=source.replace('branch=main', 'branch=main&branch=main'))]):
        rejects(check_lock, packages)
    for declaration in ({'git': repo}, {'git': repo, 'rev': 'a' * 40},
                        {'git': repo, 'branch': 'other'},
                        {'git': repo, 'branch': 'main', 'rev': 'a' * 40},
                        {'git': repo, 'branch': 'main', 'tag': 'v1'}):
        rejects(check_manifest, {'target': {'cfg(wasm)': {'dependencies': {'alias': declaration}}}})
    check_manifest({'workspace': {'dependencies': {'alias': {'git': repo, 'package': 'example', 'branch': 'main'}}}})


if __name__ == '__main__':
    self_test()
    if '--self-test' not in sys.argv:
        paths = subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0')
        for name in paths:
            path = Path(name)
            if path.name == 'Cargo.toml':
                check_manifest(tomllib.loads(path.read_text()))
            elif path.name == 'Cargo.lock':
                check_lock(tomllib.loads(path.read_text())['package'])
        print('First-party declarations follow approved owner branches; locked crate revisions are unique')
