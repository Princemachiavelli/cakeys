import json, re, subprocess
from collections import Counter
REPO = '/Users/jhoffer/srcs/cakeys-review-2026-11-24'
exec(open('/tmp/cakeys-F/scripts/density.py').read().split('# --- today')[0])
dates = {}
for h, (d, s, b) in info.items():
    dates[h] = d
R23 = '2026-11-19 20:19'; R18 = '2026-11-18 11:13'
base = REPO + '/docs/archive/REVIEW-2026-11-24/'
res = []
for X in 'ABCDE':
    t = open(base + X + '.md').read()
    for m in re.finditer(r'\n#{3,4} (%s-\d+)\. (.*?)\n(.*?)(?=\n#{2,4} |\Z)' % X, t, re.S):
        fid, title, body = m.group(1), m.group(2), m.group(3)
        why = re.search(r'Why missed:(.*?)(?:\nClass:|\n\*\*Class|\Z)', body, re.S)
        wt = why.group(1) if why else ''
        codes = sorted(set(re.findall(r'\b([TDP]-[A-Z]+)\b', wt)))
        cites = re.findall(r'`((?:crates|nix|fuzz|scripts)/[^`:\s]+\.(?:rs|nix|sh)):(\d+)(?:-(\d+))?', body[:1500])
        old23 = old18 = n = 0
        for path, a, b in cites[:4]:
            a = int(a); b = int(b) if b else a
            if b - a > 80: b = a + 80
            o = subprocess.run(['git', '-C', REPO, 'blame', '-w', '-M', '-C', '-l', '-s', '-L', f'{a},{b}', 'HEAD', '--', path], capture_output=True, text=True).stdout
            for l in o.split('\n'):
                if not l.strip(): continue
                h = l.split()[0].lstrip('^')[:7]
                d = dates.get(h)
                if not d: continue
                n += 1; old23 += d <= R23; old18 += d <= R18
        prior_ref = bool(re.search(r"(2026-11-(1[0-9]|2[0-3])|prior|\b11-23\b|\b11-18\b|'s fix|fix of|fixed in|F\d\b|\b[A-D]-\d+'s)", title + ' ' + body[:800]))
        sev = re.search(r'— (critical|high|medium|low)', title)
        res.append(dict(id=fid, sev=sev.group(1) if sev else '?', codes=codes, n=n, old23=old23, old18=old18, prior_ref=prior_ref, title=title[:120]))
json.dump(res, open('/tmp/cakeys-F/today2.json', 'w'), indent=1)
N = len(res)
print('today findings', N, Counter(r['sev'] for r in res))
wl = [r for r in res if r['n']]
print('blameable', len(wl))
print('majority of cited lines existed at the 11-23 review commit: %d/%d; at 11-18: %d/%d' % (
    sum(1 for r in wl if r['old23'] * 2 >= r['n']), len(wl), sum(1 for r in wl if r['old18'] * 2 >= r['n']), len(wl)))
print('any cited line existed at 11-23: %d/%d' % (sum(1 for r in wl if r['old23']), len(wl)))
print('P-REVIEW tagged by reviewer:', sum(1 for r in res if 'P-REVIEW' in r['codes']))
print('P-UNRUN tagged:', sum(1 for r in res if 'P-UNRUN' in r['codes']))
print('names a prior finding/fix:', sum(1 for r in res if r['prior_ref']))
c = Counter(x for r in res for x in r['codes'])
print('why-missed codes:', c.most_common())
print('findings without codes:', [r['id'] for r in res if not r['codes']])
for r in res:
    print(r['id'], r['sev'][:3], 'n=%d old23=%d old18=%d' % (r['n'], r['old23'], r['old18']), 'prior' if r['prior_ref'] else '-', ','.join(r['codes']), '|', r['title'][:70])
