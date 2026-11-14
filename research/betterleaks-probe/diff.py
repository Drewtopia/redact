"""Compare v1.10.1 and v2-main regexes: cross-match generated samples.
Usage: python diff.py <v1.toml> <v2.toml> <out.tsv>"""
import random, re, sys, tomllib
sys.path.insert(0, __import__("os").path.dirname(__file__))
from probe import translate, flags_of, Gen, sre_parse, secret_of

def comp(rx):
    p, fl = flags_of(translate(rx))
    return re.compile(p, fl), sre_parse.parse(p, fl), fl

def samples(rx, rid, n=40):
    cre, tree, fl = comp(rx)
    rng = random.Random(f"d:{rid}"); out = []
    for _ in range(n * 3):
        s = Gen(rng, bool(fl & re.I)).seq(list(tree), tail=True)
        m = cre.search(s)
        if m: out.append(secret_of(m, 0)[0])
        if len(out) >= n: break
    return out

def rate(rx, secs):
    cre = comp(rx)[0]
    return sum(1 for s in secs if cre.search(s) and secret_of(cre.search(s), 0)[0] == s) / max(len(secs), 1)

a = {r["id"]: r for r in tomllib.load(open(sys.argv[1], "rb"))["rules"]}
b = {r["id"]: r for r in tomllib.load(open(sys.argv[2], "rb"))["rules"]}
with open(sys.argv[3], "w") as out:
    out.write("id\tstatus\tv1_in_v2\tv2_in_v1\n")
    for rid in sorted(set(a) | set(b)):
        if rid not in b: out.write(f"{rid}\tremoved-in-v2\t\t\n"); continue
        if rid not in a: out.write(f"{rid}\tnew-in-v2\t\t\n"); continue
        ra, rb = a[rid].get("regex"), b[rid].get("regex")
        if ra == rb: out.write(f"{rid}\tsame\t\t\n"); continue
        try:
            x = rate(rb, samples(ra, rid)); y = rate(ra, samples(rb, rid))
            out.write(f"{rid}\tdiffers\t{x:.2f}\t{y:.2f}\n")
        except Exception as e:
            out.write(f"{rid}\terror:{e}\t\t\n")
