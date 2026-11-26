import subprocess, glob, re
from collections import Counter
REPO = '/Users/jhoffer/srcs/cakeys-review-2026-11-24'
exec(open('/tmp/cakeys-F/scripts/density.py').read().split('# --- today')[0])
tot = rf = 0
src_tot = src_rf = 0
for p in glob.glob(REPO + '/crates/**/*.rs', recursive=True):
    rel = p[len(REPO) + 1:]
    o = subprocess.run(['git', '-C', REPO, 'blame', '-l', '-s', 'HEAD', '--', rel], capture_output=True, text=True).stdout
    for l in o.split('\n'):
        if not l.strip(): continue
        h = l.split()[0].lstrip('^')[:7]
        tot += 1; r = h in rf_commits; rf += r
        if '/tests/' not in rel:
            src_tot += 1; src_rf += r
print('HEAD crates .rs lines %d, last changed by review-fix commits %d (%.0f%%); src only %d/%d (%.0f%%)' % (tot, rf, 100*rf/tot, src_rf, src_tot, 100*src_rf/src_tot))
