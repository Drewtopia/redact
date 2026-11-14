"""Turn probe output into a per-rule table (no token values printed).

Usage: python classify.py <betterleaks.toml> <probe.json> <out.tsv>
"""
import json, re, sys, tomllib

SHAPE = ("bare", "log", "json", "table")
NAMED = ("env", "jsonname")


def verdict(x, ctxs):
    if not x["samples"]:
        return "n/a"
    cells = [s["ctx"][c]["hidden"] for s in x["samples"] for c in ctxs]
    return "covered" if all(cells) else ("missed" if not any(cells) else "partly")


def kind(rule, x):
    """prefix: a keyword sits inside the secret itself (a token prefix or fixed
    structure). context: keywords only sit around the secret (a vendor name
    before `=`). none: no keyword in any sample."""
    kws = [k.lower() for k in rule.get("keywords", [])]
    inside = outside = False
    for s in x["samples"]:
        sec, m = s["secret"].lower(), s["match"].lower()
        hit_in = [k for k in kws if k in sec]
        if hit_in:
            inside = True
        elif any(k in m for k in kws):
            outside = True
    if inside and not outside:
        return "prefix"
    if inside:
        return "mixed"
    return "context" if outside else "none"


def main():
    rules = {r["id"]: r for r in tomllib.load(open(sys.argv[1], "rb"))["rules"]}
    res = json.load(open(sys.argv[2]))
    rows = []
    for x in res:
        r = rules[x["id"]]
        f = r.get("filter", "")
        ent = re.findall(r"entropy\([^)]*\)\s*<=?\s*([0-9.]+)", f)
        allow = len(re.findall(r"matchesAny|containsAny|tokenRatio|failsTokenEfficiency", f))
        fired = sorted({ru for s in x["samples"] for c in SHAPE for ru in s["ctx"][c]["rules"]})
        kw = ",".join(r.get("keywords", []))
        slen = max((len(s["secret"]) for s in x["samples"]), default=0)
        rows.append([
            x["id"], verdict(x, SHAPE), verdict(x, NAMED), kind(r, x),
            r.get("confidence", ""), "skip" if r.get("skipReport") else "",
            ent[0] if ent else "", str(allow), str(slen), kw, " ".join(fired),
            "validate" if r.get("validate") else "",
        ])
    with open(sys.argv[3], "w") as out:
        out.write("\t".join(["id", "shape", "named", "kind", "confidence", "skipReport",
                             "entropy", "allowlist_terms", "secret_len", "keywords",
                             "redact_rules", "validate"]) + "\n")
        for row in rows:
            out.write("\t".join(row) + "\n")


if __name__ == "__main__":
    main()
