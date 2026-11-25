import json, re, subprocess, sys
from collections import Counter, defaultdict
sys.path.insert(0, '/tmp/cakeys-F/scripts')
REPO = '/Users/jhoffer/srcs/cakeys-review-2026-11-24'
exec(open('/tmp/cakeys-F/scripts/density.py').read().split('# --- today')[0])  # info, is_review_fix, rf_commits
today = []
base = REPO + '/docs/archive/REVIEW-2026-11-24/'
for X in 'ABCDE':
    t = open(base + X + '.md').read()
    for m in re.finditer(r'\n#{3,4} (%s-\d+)\. (.*?)\n(.*?)(?=\n#{2,4} |\Z)' % X, t, re.S):
        today.append((m.group(1), m.group(2), m.group(3)))
def rnd(h):
    d = info[h][0]
    for name, lim in [('11-11', '2026-11-13 14:38'), ('11-13', '2026-11-15 16:29'), ('11-15', '2026-11-16 01:35'),
                      ('11-16', '2026-11-18 12:00'), ('11-18', '2026-11-23 19:34'), ('11-23', '2026-12-01')]:
        if d < lim:
            return name
full = {}
out = []
for fid, title, body in today:
    cites = re.findall(r'`((?:crates|nix|fuzz|scripts)/[^`:\s]+\.(?:rs|nix|sh)):(\d+)(?:-(\d+))?', body[:1500])
    commits = Counter(); lines = 0
    for path, a, b in cites[:4]:
        a = int(a); b = int(b) if b else a
        if b - a > 80: b = a + 80
        try:
            o = subprocess.run(['git', '-C', REPO, 'blame', '-w', '-M', '-C', '-l', '-s', '-L', f'{a},{b}', 'HEAD', '--', path],
                               capture_output=True, text=True, timeout=30).stdout
        except Exception:
            continue
        for l in o.split('\n'):
            if l.strip():
                h = l.split()[0].lstrip('^')[:7]
                commits[h] += 1; lines += 1
    hs = [h for h in commits if h in info]
    rf = [h for h in hs if h in rf_commits]
    rfl = sum(commits[h] for h in rf)
    rounds = sorted(set(rnd(h) for h in rf))
    out.append(dict(id=fid, cites=len(cites), lines=lines, rf_lines=rfl, rf=rf, rounds=rounds,
                    frac=(rfl / lines if lines else None)))
n = len(out); withc = [o for o in out if o['lines']]
anyrf = [o for o in withc if o['rf']]
maj = [o for o in withc if o['frac'] and o['frac'] >= 0.5]
print('today findings', n, 'with blameable cites', len(withc))
print('cited lines last changed by a review-fix commit: any line %d/%d (%.0f%%), majority of lines %d/%d (%.0f%%)' % (
    len(anyrf), len(withc), 100 * len(anyrf) / len(withc), len(maj), len(withc), 100 * len(maj) / len(withc)))
tl = sum(o['lines'] for o in withc); trl = sum(o['rf_lines'] for o in withc)
print('all cited lines: %d, by review-fix commits %d (%.0f%%)' % (tl, trl, 100 * trl / tl))
rc = Counter(r for o in anyrf for r in o['rounds'])
print('review-fix round of the commit that last touched the cited lines (findings may count in several):', dict(rc))
top = Counter(h for o in withc for h in o['rf'])
print('review-fix commits most often under today\'s cited lines:', [(h, c, info[h][1][:50]) for h, c in top.most_common(8)])
for o in out:
    print(o['id'], o['lines'], o['rf_lines'], ','.join(o['rf'][:4]), o['rounds'])
json.dump(out, open('/tmp/cakeys-F/blame.json', 'w'), indent=1)
