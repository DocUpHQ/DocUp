#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit the hostile archive fixtures for the abuse corpus (SPEC 8.8.2).

Binary artefacts are generated rather than committed, so the *mutation* is the
reviewable artefact and git stays text. Each builder name matches a `builder`
field in corpus.json.

Usage:  python build_archives.py [outdir]
Default outdir is ../_generated/archives (git-ignored).
"""
import io
import os
import sys
import tarfile

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '_generated', 'archives')

HTML = b'<!doctype html><html><head></head><body>ok</body></html>\n'


def _f(tar, name, data=HTML, mode=0o644):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    tar.addfile(ti, io.BytesIO(data))


def _link(tar, name, target, kind):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE if kind == 'sym' else tarfile.LNKTYPE
    ti.linkname = target
    ti.mode = 0o777 if kind == 'sym' else 0o644
    tar.addfile(ti)


def _dev(tar, name):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.CHRTYPE
    ti.devmajor, ti.devminor = 1, 3          # /dev/null
    ti.mode = 0o666
    tar.addfile(ti)


# --- builders: each returns nothing, writes one archive ---------------------

def zip_slip(tar):
    """A member whose path escapes the extraction root."""
    _f(tar, 'html/index.html')
    _f(tar, '../../../../etc/cron.d/pwned', b'* * * * * root id\n')


def absolute_symlink(tar):
    _f(tar, 'html/index.html')
    _link(tar, 'html/passwd', '/etc/passwd', 'sym')


def relative_symlink_escape(tar):
    _f(tar, 'html/index.html')
    _link(tar, 'html/escape', '../../../../etc/passwd', 'sym')


def hardlink(tar):
    _f(tar, 'html/index.html')
    _link(tar, 'html/hard', '/etc/passwd', 'lnk')


def ratio_bomb(tar):
    """~120 MB of zeroes: compresses to almost nothing, blows the ratio cap."""
    _f(tar, 'html/index.html')
    _f(tar, 'html/bomb.bin', b'\0' * (120 * 1024 * 1024))


def reserved_user_ini(tar):
    _f(tar, 'html/index.html')
    _f(tar, 'html/.user.ini', b'auto_prepend_file=/tmp/x.php\n')


def reserved_htaccess(tar):
    _f(tar, 'html/index.html')
    _f(tar, 'html/.htaccess', b'AddHandler application/x-httpd-php .html\n')


def php_file(tar):
    _f(tar, 'html/index.html')
    _f(tar, 'html/shell.php', b'<?php system($_GET["c"]); ?>\n')


def device_node(tar):
    _f(tar, 'html/index.html')
    _dev(tar, 'html/null')


def missing_index(tar):
    """Valid tree with no html/index.html - SPEC 8.4.5 makes it mandatory."""
    _f(tar, 'html/guide.html')


def two_pdf_files(tar):
    """SPEC 8.4.5: exactly one file per offline format directory."""
    _f(tar, 'html/index.html')
    _f(tar, 'pdf/one.pdf', b'%PDF-1.7\n')
    _f(tar, 'pdf/two.pdf', b'%PDF-1.7\n')


def overlong_name(tar):
    _f(tar, 'html/index.html')
    _f(tar, 'html/' + ('a' * 300) + '.html')


BUILDERS = [zip_slip, absolute_symlink, relative_symlink_escape, hardlink,
            ratio_bomb, reserved_user_ini, reserved_htaccess, php_file,
            device_node, missing_index, two_pdf_files, overlong_name]


def main():
    os.makedirs(OUT, exist_ok=True)
    for b in BUILDERS:
        path = os.path.join(OUT, b.__name__ + '.tar.gz')
        with tarfile.open(path, 'w:gz') as tar:
            b(tar)
        print('%-28s %9d bytes  %s' % (b.__name__, os.path.getsize(path), (b.__doc__ or '').strip().split('\n')[0]))
    print('\n%d archives written to %s' % (len(BUILDERS), os.path.abspath(OUT)))
    print('NOTE: these are hostile by design. Never extract them with a stock')
    print('extractor; they exist to be REJECTED by the ArtifactIngestor.')


if __name__ == '__main__':
    main()
