"""Probe redact against every Betterleaks rule.

For each rule: generate fake tokens from its regex, place them in several
contexts, run `redact scan --json`, and check whether the secret's bytes
fall inside redact's spans.

Usage: python probe.py <betterleaks.toml> <redact binary> <redact config> <out.json>
"""
import json, random, re, string, subprocess, sys, tomllib
from concurrent.futures import ThreadPoolExecutor

try:
    import re._parser as sre_parse
    import re._constants as C
except ImportError:  # pragma: no cover
    import sre_parse, sre_constants as C

SEED = 48
SAMPLES = 8
PRINTABLE = [chr(c) for c in range(0x20, 0x7F)]
ALNUM = string.ascii_letters + string.digits


def translate(rx: str) -> str:
    """Go RE2 -> Python re, close enough to parse and match."""
    rx = rx.replace("[[:alnum:]]", "[a-zA-Z0-9]").replace("[:alnum:]", "a-zA-Z0-9")
    rx = rx.replace("[[:alpha:]]", "[a-zA-Z]").replace("[:alpha:]", "a-zA-Z")
    rx = rx.replace("[[:digit:]]", "[0-9]").replace("[:digit:]", "0-9")
    rx = rx.replace(r"\z", r"\Z")
    return rx


def flags_of(rx: str):
    """Python needs global flags first; move any (?i)/(?s)/(?m) to the front."""
    fl = 0
    for m in re.finditer(r"\(\?([imsU]+)\)", rx):
        if "i" in m.group(1):
            fl |= re.I
        if "s" in m.group(1):
            fl |= re.S
        if "m" in m.group(1):
            fl |= re.M
    rx = re.sub(r"\(\?[imsU]+\)", "", rx)
    return rx, fl


def charset_items(items, ci):
    """Return the list of printable chars a class accepts."""
    neg = False
    chars = set()
    for op, av in items:
        if op is C.NEGATE:
            neg = True
        elif op is C.LITERAL:
            chars.add(chr(av))
        elif op is C.RANGE:
            lo, hi = av
            for c in range(lo, min(hi, 0x7E) + 1):
                chars.add(chr(c))
        elif op is C.CATEGORY:
            if av is C.CATEGORY_DIGIT:
                chars |= set(string.digits)
            elif av is C.CATEGORY_WORD:
                chars |= set(ALNUM + "_")
            elif av is C.CATEGORY_SPACE:
                chars |= {" ", "\t"}
            elif av is C.CATEGORY_NOT_SPACE:
                chars |= set(PRINTABLE) - {" "}
            elif av is C.CATEGORY_NOT_DIGIT:
                chars |= set(PRINTABLE) - set(string.digits)
            elif av is C.CATEGORY_NOT_WORD:
                chars |= set(PRINTABLE) - set(ALNUM + "_")
    if ci:
        chars |= {c.swapcase() for c in chars if c.isalpha()}
    if neg:
        chars = set(ALNUM + "_-.") - chars or set(PRINTABLE) - chars
    return sorted(chars)


class Gen:
    def __init__(self, rng, ci):
        self.rng = rng
        self.ci = ci
        self.groups = {}

    def pick(self, chars):
        # Prefer token-ish characters so samples look like real tokens.
        good = [c for c in chars if c in ALNUM]
        if good and self.rng.random() < 0.97:
            return self.rng.choice(good)
        good = [c for c in chars if c not in "\t\r\n"]
        return self.rng.choice(good or chars)

    def seq(self, items, tail=False):
        out = []
        n = len(items)
        for i, (op, av) in enumerate(items):
            out.append(self.one(op, av, tail and i == n - 1))
        return "".join(out)

    def one(self, op, av, tail):
        r = self.rng
        if op is C.LITERAL:
            return chr(av)
        if op is C.NOT_LITERAL:
            return self.pick([c for c in ALNUM if ord(c) != av])
        if op is C.ANY:
            return self.pick(ALNUM)
        if op is C.IN:
            return self.pick(charset_items(av, self.ci))
        if op is C.AT:
            return ""
        if op in (C.MAX_REPEAT, C.MIN_REPEAT, getattr(C, "POSSESSIVE_REPEAT", None)):
            lo, hi, sub = av
            if hi is C.MAXREPEAT:
                hi = lo + 12
            # Separators such as \s* or [ \t]{0,20}: keep them short.
            if lo == 0 and len(sub) == 1 and sub[0][0] is C.IN:
                cs = charset_items(sub[0][1], self.ci)
                if not set(cs) & set(ALNUM):
                    hi = min(hi, 1)
                elif " " in cs:  # [\s\S]{0,32}?: a single space
                    return "" if tail else " "
            if lo == 0 and len(sub) == 1 and sub[0][0] is C.ANY:
                return "" if tail else " "
            k = r.randint(lo, min(hi, max(lo, lo + 24)))
            if tail and lo == 0:
                k = 0
            return "".join(self.seq(sub) for _ in range(k))
        if op is C.SUBPATTERN:
            gid, _add, _del, sub = av
            s = self.seq(sub, tail)
            if gid:
                self.groups[gid] = s
            return s
        if op is C.BRANCH:
            _, branches = av
            if tail:
                for b in branches:
                    if all(o is C.AT for o, _ in b):
                        return ""
            return self.seq(r.choice(branches), tail)
        if op is C.GROUPREF:
            return self.groups.get(av, "")
        if op in (C.ASSERT, C.ASSERT_NOT):
            return ""
        raise ValueError(f"unsupported op {op}")


def literal_runs(items, inside=False, acc=None, cur=None):
    """Longest literal run inside / outside capture group 1 (rough)."""
    if acc is None:
        acc = {"in": 0, "out": 0}
    run = []
    for op, av in items:
        if op is C.LITERAL:
            run.append(chr(av))
            acc["in" if inside else "out"] = max(acc["in" if inside else "out"], len(run))
        else:
            run = []
            if op is C.SUBPATTERN:
                literal_runs(av[3], inside or av[0] == 1, acc)
            elif op is C.BRANCH:
                for b in av[1]:
                    literal_runs(b, inside, acc)
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT) and av[0] >= 1:
                literal_runs(av[2], inside, acc)
    return acc


def secret_of(m, secret_group):
    if secret_group:
        return m.group(secret_group), m.span(secret_group)
    if m.re.groups:
        for g in range(1, m.re.groups + 1):
            if m.group(g):
                return m.group(g), m.span(g)
    return m.group(0), m.span(0)


def contexts(match, secret):
    """(name, text) pairs. Shape contexts carry the rule's full match; named
    contexts carry only the secret behind a name that says token."""
    return [
        ("bare", match),
        ("log", f"2026-11-14T09:12:44Z INFO loaded {match} from cache"),
        ("json", '{"id": "' + match + '", "ok": true}'),
        ("table", f"1   {match}   2026-11-14   active"),
        ("env", f"export DEPLOY_TOKEN={secret}"),
        ("jsonname", '{"api_key": "' + secret + '"}'),
    ]
SHAPE = ("bare", "log", "json", "table")


def run_redact(binary, config, text):
    p = subprocess.run([binary, "-c", config, "scan", "--json"], input=text.encode(),
                       capture_output=True, timeout=30)
    return json.loads(p.stdout or b"[]")


def hidden(text, secret, spans):
    """Secret counts as hidden when no run of more than 6 of its bytes is left
    outside redact's spans (a visible prefix such as `glpat-` is fine)."""
    b = text.encode()
    s = secret.encode()
    start = b.find(s)
    if start < 0:
        return False, []
    covered = [False] * len(s)
    rules = set()
    for sp in spans:
        lo, hi = max(sp["start"], start), min(sp["end"], start + len(s))
        if lo < hi:
            rules.add(f'{sp["pack"]}:{sp["rule"]}')
            for i in range(lo - start, hi - start):
                covered[i] = True
    run = best = 0
    for c in covered:
        run = 0 if c else run + 1
        best = max(best, run)
    limit = 6 if len(s) > 12 else 0
    return best <= limit, sorted(rules)


def probe_rule(rule, binary, config):
    out = {"id": rule["id"], "samples": [], "errors": []}
    rx = rule.get("regex")
    if not rx:
        out["errors"].append("no regex")
        return out
    prx, fl = flags_of(translate(rx))
    try:
        cre = re.compile(prx, fl)
        tree = sre_parse.parse(prx, fl)
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"compile: {e}")
        return out
    out["lit"] = literal_runs(list(tree))
    rng = random.Random(f"{SEED}:{rule['id']}")
    tries = 0
    while len(out["samples"]) < SAMPLES and tries < 60:
        tries += 1
        g = Gen(rng, bool(fl & re.I))
        try:
            s = g.seq(list(tree), tail=True)
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"gen: {e}")
            break
        if "\n" in s.strip("\n"):
            pass  # multi-line rules (private keys) are fine
        m = cre.search(s)
        if not m:
            continue
        secret, _ = secret_of(m, rule.get("secretGroup", 0))
        if len(secret) < 4:
            continue
        sample = {"match": m.group(0), "secret": secret, "ctx": {}}
        for name, text in contexts(m.group(0).strip(), secret):
            spans = run_redact(binary, config, text + "\n")
            ok, rules = hidden(text, secret, spans)
            sample["ctx"][name] = {"hidden": ok, "rules": rules}
        out["samples"].append(sample)
    if not out["samples"]:
        out["errors"].append("no matching sample generated")
    return out


def main():
    cfg_path, binary, config, out_path = sys.argv[1:5]
    rules = tomllib.load(open(cfg_path, "rb"))["rules"]
    with ThreadPoolExecutor(12) as ex:
        res = list(ex.map(lambda r: probe_rule(r, binary, config), rules))
    json.dump(res, open(out_path, "w"), indent=1)
    print(len(res), "rules probed;", sum(1 for r in res if r["errors"]), "with errors")


if __name__ == "__main__":
    main()
