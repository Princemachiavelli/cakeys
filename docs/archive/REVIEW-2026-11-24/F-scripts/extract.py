#!/usr/bin/env python3
"""Extract every prior finding into findings.json: review, id, area, sev, title, text, status."""
import json, re, os, glob, sys

REPO = '/Users/jhoffer/srcs/cakeys-review-2026-11-24'
OUT = '/tmp/cakeys-F/findings.json'
F = []

def area_of(text, default='?'):
    t = text
    m = re.search(r'crates/([a-z0-9-]+)/(tests|src|examples|build\.rs|fuzz)?', t)
    if m:
        a = m.group(1)
        if m.group(2) == 'tests':
            a += '/tests'
        return a
    rules = [
        (r'\bfuzz', 'fuzz'),
        (r'flake\.nix|nix/|\.nix\b|workflow|\bCI\b|checks\.nix|apps\.nix', 'nix-ci'),
        (r'scripts/', 'scripts'),
        (r'tpm2_ptool|tpm-certify|tpm2-pkcs11|swtpm|\bTPM\b', 'tpm2-pkcs11'),
        (r'ykcs11|PIV|YubiKey|piv-', 'ykcs11'),
        (r'kmsp11|Cloud KMS', 'kmsp11'),
        (r'camigrate|migrate|transport|bundle|import|export|keyfile|PKCS#12', 'camigrate'),
        (r'caprobe|probe|supports|profile row|emitter', 'caprobe'),
        (r'p11-fault|fault shim', 'p11-fault'),
        (r'profile|effective\.rs', 'profile'),
        (r'token\.rs|token/|ops\.rs|gate\.rs|provider|templates\.rs|session|C_Login|C_Find|CKR_', 'pkcs11'),
        (r'config\.rs|id\.rs|reconcile|lock|keys\.toml|plan\.rs|chain\.rs|pop\.rs|spec digest|commitment', 'core'),
        (r'README|DESIGN|ARCHITECTURE|docs/|\.md\b', 'docs'),
        (r'\bverb|cakeys |--|exit \d', 'cli'),
    ]
    for pat, a in rules:
        if re.search(pat, t):
            return a
    return default

def add(review, id_, sev, title, text, status='', area=None, file=None):
    F.append(dict(review=review, id=id_, sev=sev, title=title.strip(), text=text,
                  status=status, area=area or area_of(title + ' ' + text), file=file or ''))

def rd(p):
    return open(os.path.join(REPO, p)).read()

# ---- 2026-11-11 ----
t = rd('docs/archive/REVIEW-2026-11-11.md')
for line in t.split('\n'):
    m = re.match(r'^\| ([HMLPDS]\d+b?) \| ([HMLD]) \| (.*)\|\s*$', line)
    if not m:
        continue
    cols = [c.strip() for c in m.group(3).split(' | ')]
    if len(cols) >= 5:   # main table: where, finding, evidence, rec, status
        where, finding, status = cols[0], cols[1], cols[-1]
        add('11-11', m.group(1), m.group(2), finding[:160], where + ' ' + ' | '.join(cols), status,
            area=area_of(where + ' ' + finding))
    else:                # lock table: finding, status
        finding, status = cols[0], cols[-1]
        add('11-11', m.group(1), m.group(2), finding[:160], ' | '.join(cols), status, area='core')

# ---- 2026-11-13 ----
t = rd('docs/archive/REVIEW-2026-11-13.md')
fsec = t.split('## Findings', 1)[1].split('## Threat model')[0]
status = {}
for line in t.split('## Status')[1].split('## A3')[0].split('\n'):
    m = re.match(r'^\| (A\d+(?:, A\d+)*) \| (.*) \|$', line)
    if m:
        for i in m.group(1).split(', '):
            status[i] = m.group(2)
for line in fsec.split('\n'):
    m = re.match(r'^\| (A\d+) \| ([HML]) \| (.*)\|\s*$', line)
    if m:
        cols = [c.strip() for c in m.group(3).split(' | ')]
        add('11-13', m.group(1), m.group(2), cols[0][:160], ' | '.join(cols), status.get(m.group(1), ''),
            area=area_of(cols[1] + ' ' + cols[0]) if len(cols) > 1 else None)

# ---- 2026-11-15 ----
t = rd('docs/archive/REVIEW-2026-11-15.md')
parts = re.split(r'\n(?=### )', t)
for p in parts:
    m = re.match(r'### ([A-Z]\d+)\. (.*)', p)
    if m:
        body = p.split('\n', 1)[1] if '\n' in p else ''
        body = re.split(r'\n## ', body)[0]
        sev = 'run' if '[run]' in m.group(2) else 'read'
        add('11-15', m.group(1), sev, m.group(2), body, '')

# ---- ISSUES.md 2026-11-16 (B and Q items) ----
t = rd('ISSUES.md')
seen = set()
for line in t.split('\n'):
    m = re.match(r'^\| (B\d+|Q\d+)(, (Q\d+))?(, in part| , rest|, rest)? \| (.*) \|$', line)
    if m:
        for i in [m.group(1), m.group(3)]:
            if i and i not in seen:
                seen.add(i)
                add('11-16', i, 'B' if i.startswith('B') else 'Q', m.group(5)[:160], m.group(5), 'fixed')
parts = re.split(r'\n(?=- \*\*)', t)
for p in parts:
    m = re.match(r'- \*\*([BQ]\d+)\.? ?(.*?)\*\*', p)
    if m and m.group(1) not in seen:
        seen.add(m.group(1))
        st = 'done' if re.search(r'\*\*Done', p) else 'open'
        add('11-16', m.group(1), 'B' if m.group(1)[0] == 'B' else 'Q', m.group(2)[:160], p[:3000], st)
# Q items that are only in the first version
t0 = open('/tmp/cakeys-F/ISSUES-2120ec1.md').read()
for p in re.split(r'\n(?=- \*\*)', t0):
    m = re.match(r'- \*\*([BQ]\d+)\.? ?(.*?)\*\*', p)
    if m and m.group(1) not in seen:
        seen.add(m.group(1))
        add('11-16', m.group(1), m.group(1)[0], m.group(2)[:160], p[:3000], 'open')

# ---- 2026-11-18 review/ ----
for path in sorted(glob.glob('/tmp/cakeys-F/review/REVIEW_*.md')):
    name = os.path.basename(path)
    if name in ('REVIEW_INDEX.md', 'REVIEW_DESIGN.md'):
        continue
    src = name[len('REVIEW_'):-3]
    t = open(path).read()
    head = t.split('\n', 1)[0]
    m0 = re.match(r'# Review: (\S+)', head)
    realpath = m0.group(1) if m0 else src
    parts = re.split(r'\n(?=### )', t)
    for p in parts:
        m = re.match(r'### (F\d+)\. (.*) — (bug|risk|practice|complexity|nit)\s*$', p.split('\n', 1)[0])
        if not m:
            continue
        body = p.split('\n', 1)[1] if '\n' in p else ''
        body = re.split(r'\n## ', body)[0]
        ver = re.search(r'\*\*Verification:\*\*\s*(.*)', body)
        sev = m.group(3)
        if ver:
            v = ver.group(1)
            if 'withdrawn' in v[:40]:
                sev = 'withdrawn'
            else:
                dm = re.search(r'downgraded to (\w+)|moved to (\w+)|re-graded (?:down )?to (\w+)', v[:120])
                if dm:
                    sev = [g for g in dm.groups() if g][0]
        st = 'fixed' if re.search(r'\*\*Fixed', body) else 'open'
        a = area_of(realpath + ' ' + body)
        if realpath.startswith('crates/'):
            seg = realpath.split('/')
            a = seg[1] + ('/tests' if len(seg) > 2 and seg[2] == 'tests' else '')
        elif realpath.startswith('nix/') or realpath.endswith('.nix') or realpath.startswith('.github') \
                or realpath.startswith('.config') or realpath in ('Cargo.toml', 'deny.toml'):
            a = 'nix-ci'
        elif realpath.startswith('scripts/') or realpath.startswith('examples/') or realpath.startswith('upstream/'):
            a = 'scripts'
        elif realpath.startswith('fuzz'):
            a = 'fuzz'
        add('11-18', realpath + ':' + m.group(1), sev, m.group(2), body, st, area=a, file=realpath)

# ---- 2026-11-23 ----
st23 = rd('docs/archive/REVIEW-2026-11-23.md')
for X in 'ABCD':
    t = rd(f'docs/archive/REVIEW-2026-11-23/{X}.md')
    parts = re.split(r'\n(?=### )', t)
    for p in parts:
        m = re.match(rf'### ({X}-\d+)\. (.*?) — (critical|high|medium|low) — ', p.split('\n', 1)[0])
        if not m:
            continue
        body = p.split('\n', 1)[1] if '\n' in p else ''
        body = re.split(r'\n## ', body)[0]
        fm = re.search(r'`((?:crates|nix|docs|scripts|fuzz|\.github)/[^`:\s]+)', body)
        fpath = fm.group(1) if fm else ''
        a = area_of(fpath + ' ' + m.group(2) + ' ' + body[:400])
        if fpath.startswith('crates/'):
            seg = fpath.split('/')
            a = seg[1] + ('/tests' if len(seg) > 2 and seg[2] == 'tests' else '')
        add('11-23', m.group(1), m.group(3), m.group(2), body, '', area=a, file=fpath)

json.dump(F, open(OUT, 'w'), indent=1)
from collections import Counter
print(len(F), Counter(f['review'] for f in F))
print(Counter((f['review'], f['sev']) for f in F))
