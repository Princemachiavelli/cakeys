import re, sys, json, subprocess
from collections import defaultdict, Counter
REPO = '/Users/jhoffer/srcs/cakeys-review-2026-11-24'
lines = open('/tmp/cakeys-F/numstat.txt').read().split('\n')
commits = []
cur = None
for l in lines:
    if l.startswith('@@'):
        h, d, s = l[2:].split('|', 2)
        cur = dict(h=h, d=d, s=s, files=[])
        commits.append(cur)
    elif l.strip() and cur is not None:
        p = l.split('\t')
        if len(p) == 3:
            a, r, f = p
            a = 0 if a == '-' else int(a); r = 0 if r == '-' else int(r)
            if '=>' in f:  # rename
                f = re.sub(r'\{[^{}]*=> ([^{}]*)\}', r'\1', f).replace('//', '/')
                f = f.split(' => ')[-1]
            cur['files'].append((a, r, f))

def kind(f):
    if f.endswith('.rs'):
        if re.search(r'(^|/)tests/|(^|/)fuzz/|/benches/', f):
            return 'test'
        return 'src'
    if f.endswith('.md'):
        return 'docs'
    if f.endswith('.nix') or f.startswith('.github') or f.endswith('.sh') or f.endswith('.yml'):
        return 'nix/ci/sh'
    if re.search(r'profiles?/|\.toml$|\.lock$|\.txt$|\.json$', f):
        return 'data'
    return 'other'

msgs = open('/tmp/cakeys-F/messages.txt').read().split('@@')[1:]
body = {}
for m in msgs:
    head, _, b = m.partition('\n')
    body[head.split('|')[0]] = b

def ctype(c):
    s = c['s']; b = body.get(c['h'], '')
    if s.startswith('CHECKPOINT') or s.startswith('Merge'):
        return 'checkpoint/merge'
    if re.search(r'^docs|^docs/|^review|REVIEW|archive', s) and not re.search(r'fix', s, re.I):
        return 'docs/review'
    if re.search(r'review|fix|\bF\d\b|\b[ABCDVNPSHLMQ]-?\d+\b|finding|regress|wrong|broken|refuse', s, re.I):
        return 'fix'
    if re.search(r'^tests?:|coverage|mutants|test', s, re.I):
        return 'test'
    if re.search(r'refactor|split|move|one |rename|dedup|remove|delete|clean', s, re.I):
        return 'refactor'
    return 'feature'

# per day
day = defaultdict(lambda: Counter())
for c in commits:
    d = c['d'][:10]
    day[d]['commits'] += 1
    day[d][ctype(c)] += 1
    for a, r, f in c['files']:
        k = kind(f)
        day[d]['+' + k] += a
        day[d]['-' + k] += r
print('| day | commits | fix | feature | refactor | test | docs/review | ckpt/merge | +src.rs | +test.rs(tests/) | +docs | net src | net test |')
print('|---|' + '---:|' * 12)
tot = Counter()
for d in sorted(day):
    x = day[d]; tot.update(x)
    print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (d[5:], x['commits'], x['fix'], x['feature'], x['refactor'], x['test'], x['docs/review'], x['checkpoint/merge'], x['+src'], x['+test'], x['+docs'], x['+src'] - x['-src'], x['+test'] - x['-test']))
x = tot
print('| total | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (x['commits'], x['fix'], x['feature'], x['refactor'], x['test'], x['docs/review'], x['checkpoint/merge'], x['+src'], x['+test'], x['+docs'], x['+src'] - x['-src'], x['+test'] - x['-test']))
alladd = sum(a for c in commits for a, r, f in c['files']); alldel = sum(r for c in commits for a, r, f in c['files'])
print('all lines added', alladd, 'deleted', alldel, 'days', len(day))

# between reviews: windows by review commit time
W = [('<11-11 review', '2026-11-11 00:00', '2026-11-11 18:21'),
     ('11-11..11-13', '2026-11-11 18:21', '2026-11-13 14:38'),
     ('11-13..11-15', '2026-11-13 14:38', '2026-11-15 12:00'),
     ('11-15..11-16', '2026-11-15 12:00', '2026-11-16 01:35'),
     ('11-16..11-18', '2026-11-16 01:35', '2026-11-18 12:00'),
     ('11-18..11-23', '2026-11-18 12:00', '2026-11-23 19:34'),
     ('11-23..11-24', '2026-11-23 19:34', '2026-11-25 00:00')]
print('\n| window | commits | fix | feature | refactor | test | +src | +tests/ | src net | tests/ net |')
for name, a, b in W:
    cs = [c for c in commits if a <= c['d'] < b]
    ct = Counter(ctype(c) for c in cs)
    s = Counter()
    for c in cs:
        for ad, r, f in c['files']:
            s['+' + kind(f)] += ad; s['-' + kind(f)] += r
    print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (name, len(cs), ct['fix'], ct['feature'], ct['refactor'], ct['test'], s['+src'], s['+test'], s['+src'] - s['-src'], s['+test'] - s['-test']))

# per-file churn
churn = Counter(); nrev = Counter(); fixchurn = Counter()
for c in commits:
    isfix = ctype(c) == 'fix'
    for a, r, f in c['files']:
        churn[f] += a + r; nrev[f] += 1
        if isfix:
            fixchurn[f] += 1
json.dump(dict(churn=churn, nrev=nrev, fixchurn=fixchurn, types={c['h']: ctype(c) for c in commits}), open('/tmp/cakeys-F/churn.json', 'w'))
print('\ntop churn .rs files (lines added+deleted, commits touching, fix commits touching)')
for f, n in [x for x in churn.most_common() if x[0].endswith('.rs')][:25]:
    print(n, nrev[f], fixchurn[f], f)
print('\ncommit types', Counter(ctype(c) for c in commits))
