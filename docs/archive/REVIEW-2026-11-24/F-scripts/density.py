import json, re, glob, os, math
from collections import Counter, defaultdict
REPO = '/Users/jhoffer/srcs/cakeys-review-2026-11-24'
F = json.load(open('/tmp/cakeys-F/final.json'))
# --- commits, review-fix commits ---
msgs = open('/tmp/cakeys-F/messages.txt').read().split('@@')[1:]
info = {}
for m in msgs:
    head, _, b = m.partition('\n')
    h, d, s = head.split('|', 2)
    info[h] = (d, s, b)
def is_review_fix(h):
    d, s, b = info[h]
    if d < '2026-11-11 18:00':
        return False
    if re.match(r'(docs(/archive)?:|CHECKPOINT|Merge)', s) and not re.search(r'fix', s, re.I):
        return False
    return bool(re.search(r"\(review\b|review [A-Z§]|review's|Review (pass|fixes|follow-up)|review 2026|WIP checkpoint|\b(H1b?|M[1-4]|L\d+|S\d+|A\d+|V\d|N\d|C\d|P\d|B\d+|Q\d+|D\d)\b[:/,)]|\b[ABCD]-\d+\b", s + '\n' + b))
numstat = open('/tmp/cakeys-F/numstat.txt').read().split('\n')
churn = Counter(); touches = Counter(); rf_touch = Counter(); rf_churn = Counter(); cur = None
rf_commits = set()
for l in numstat:
    if l.startswith('@@'):
        cur = l[2:].split('|')[0]
        if is_review_fix(cur):
            rf_commits.add(cur)
    elif l.strip() and cur:
        p = l.split('\t')
        if len(p) == 3:
            a, r, f = p
            a = 0 if a == '-' else int(a); r = 0 if r == '-' else int(r)
            if '=>' in f:
                f = re.sub(r'\{[^{}]*=> ([^{}]*)\}', r'\1', f).replace('//', '/').split(' => ')[-1]
            churn[f] += a + r; touches[f] += 1
            if cur in rf_commits:
                rf_touch[f] += 1; rf_churn[f] += a + r
print('review-fix commits:', len(rf_commits), 'of', len(info))
rfl = sum(rf_churn.values()); allc = sum(churn.values())
print('lines changed by review-fix commits: %d of %d (%.0f%%)' % (rfl, allc, 100 * rfl / allc))

# --- today's findings with their cited path ---
base = REPO + '/docs/archive/REVIEW-2026-11-24/'
today = []
for X in 'ABCDE':
    t = open(base + X + '.md').read()
    for m in re.finditer(r'\n#{3,4} (%s-\d+)\. (.*?)\n(.*?)(?=\n#{2,4} |\Z)' % X, t, re.S):
        fid, title, body = m.group(1), m.group(2), m.group(3)
        paths = re.findall(r'`((?:crates|nix|docs|scripts|fuzz|\.github|flake\.nix|checks\.nix|apps\.nix)[^`:\s]*)', body[:600])
        sev = re.search(r'— (critical|high|medium|low)', title)
        why = re.search(r'Why missed:(.*?)(?:\nClass:|\Z)', body, re.S)
        codes = re.findall(r'\b([TDP]-[A-Z]+)\b', why.group(1)) if why else []
        today.append(dict(id=fid, title=title, paths=paths, sev=sev.group(1) if sev else '?', codes=codes, body=body))
json.dump(today, open('/tmp/cakeys-F/today.json', 'w'), indent=1)
print('today findings parsed:', len(today), Counter(x['id'][0] for x in today))

def norm(p):
    p = p.rstrip('.,;)')
    return p
# finding count per file: prior (11-18 file + 11-23 first path) and today (first path)
prior = Counter(); tod = Counter()
for f in F:
    if f['review'] in ('11-18', '11-23') and f.get('file'):
        prior[norm(f['file'])] += 1
for x in today:
    if x['paths']:
        tod[norm(x['paths'][0])] += 1
# map renamed files: config.rs -> config/, ops.rs -> ops/mod.rs: compare by crate/module stem
def stem(p):
    p = re.sub(r'/mod\.rs$', '', p); p = re.sub(r'\.rs$', '', p)
    return p
cs = Counter(); ts = Counter(); rfs = Counter(); ps = Counter(); tds = Counter()
for f, n in churn.items():
    if f.endswith('.rs'):
        cs[stem(f)] += n; ts[stem(f)] += touches[f]; rfs[stem(f)] += rf_touch[f]
for f, n in prior.items():
    ps[stem(f)] += n
for f, n in tod.items():
    tds[stem(f)] += n
# keep stems existing at HEAD
head = set(stem(p[len(REPO) + 1:]) for p in glob.glob(REPO + '/crates/**/*.rs', recursive=True))
rows = [(s, cs[s], ts[s], rfs[s], ps[s], tds[s]) for s in head if cs[s] > 0]
rows.sort(key=lambda r: -r[1])
N = len(rows)
def spearman(x, y):
    def rank(v):
        o = sorted(range(len(v)), key=lambda i: v[i]); r = [0] * len(v); i = 0
        while i < len(v):
            j = i
            while j + 1 < len(v) and v[o[j + 1]] == v[o[i]]:
                j += 1
            for k in range(i, j + 1):
                r[o[k]] = (i + j) / 2
            i = j + 1
        return r
    rx, ry = rank(x), rank(y); mx = sum(rx) / len(rx); my = sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den
churnv = [r[1] for r in rows]; touchv = [r[2] for r in rows]; rfv = [r[3] for r in rows]
allf = [r[4] + r[5] for r in rows]; todv = [r[5] for r in rows]
print('files (.rs stems at HEAD with churn):', N)
print('spearman churn~prior+today findings %.2f, touches~findings %.2f, reviewfix-touches~today %.2f, prior~today %.2f' % (
    spearman(churnv, allf), spearman(touchv, allf), spearman(rfv, todv), spearman([r[4] for r in rows], todv)))
# quartiles by churn
q = N // 4
for i, name in enumerate(['top quartile churn', 'Q2', 'Q3', 'bottom quartile']):
    part = rows[i * q:(i + 1) * q] if i < 3 else rows[3 * q:]
    print('%-20s files=%d churn=%d prior findings=%d today findings=%d files with today finding=%d' % (
        name, len(part), sum(r[1] for r in part), sum(r[4] for r in part), sum(r[5] for r in part), sum(1 for r in part if r[5])))
# today's findings in files touched by review-fix commits
t_in_rf = sum(r[5] for r in rows if r[3] > 0); t_all = sum(r[5] for r in rows)
f_rf = sum(1 for r in rows if r[3] > 0)
print('files touched by a review-fix commit: %d of %d; today findings in them: %d of %d (paths resolving to a HEAD .rs file)' % (f_rf, N, t_in_rf, t_all))
print('\ntop 15 by churn: stem churn touches rf-touches prior today')
for r in rows[:15]:
    print(*r)
print('\nfiles with >=2 today findings:')
for r in sorted(rows, key=lambda r: -r[5]):
    if r[5] >= 2: print(*r)
unres = [x['paths'][0] for x in today if x['paths'] and stem(norm(x['paths'][0])) not in head]
print('\ntoday findings whose first path is not a HEAD .rs file:', len(unres), Counter(p.split('/')[0] for p in unres))
print('today findings without any path:', sum(1 for x in today if not x['paths']))

# size-normalised: lines at HEAD per stem
size = Counter()
for p in glob.glob(REPO + '/crates/**/*.rs', recursive=True):
    size[stem(p[len(REPO) + 1:])] += sum(1 for _ in open(p, errors='ignore'))
rows2 = [r for r in rows if size[r[0]] >= 50]
rel_churn = [r[1] / size[r[0]] for r in rows2]
dens = [(r[4] + r[5]) * 1000 / size[r[0]] for r in rows2]
print('\nsize-normalised (n=%d files >=50 lines): spearman churn/line ~ findings/KLOC %.2f; size ~ findings %.2f; size ~ churn %.2f' % (
    len(rows2), spearman(rel_churn, dens), spearman([size[r[0]] for r in rows2], [r[4] + r[5] for r in rows2]), spearman([size[r[0]] for r in rows2], [r[1] for r in rows2])))
rows2.sort(key=lambda r: -r[1] / size[r[0]])
q = len(rows2) // 4
for i in range(4):
    part = rows2[i * q:(i + 1) * q] if i < 3 else rows2[3 * q:]
    L = sum(size[r[0]] for r in part)
    print('churn/line quartile %d: files=%d KLOC=%.1f churn/line=%.1f findings/KLOC prior=%.1f today=%.2f' % (
        i + 1, len(part), L / 1000, sum(r[1] for r in part) / L, sum(r[4] for r in part) * 1000 / L, sum(r[5] for r in part) * 1000 / L))
# rf-touch quartiles normalised
rows2.sort(key=lambda r: -r[3])
for i in range(4):
    part = rows2[i * q:(i + 1) * q] if i < 3 else rows2[3 * q:]
    L = sum(size[r[0]] for r in part)
    print('review-fix-touch quartile %d: rf touches %d-%d, today findings/KLOC=%.2f prior/KLOC=%.1f' % (
        i + 1, part[-1][3], part[0][3], sum(r[5] for r in part) * 1000 / L, sum(r[4] for r in part) * 1000 / L))
