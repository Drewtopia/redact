import json, subprocess, sys, tomllib, os, tempfile
R = sys.argv[2]
rules = tomllib.load(open(sys.argv[1], "rb"))["rules"]
bad = []
d = tempfile.mkdtemp(dir=os.path.dirname(os.path.abspath(sys.argv[3])))
for r in rules:
    if "regex" not in r: continue
    p = os.path.join(d, "t.toml")
    with open(p, "w") as f:
        f.write('schema_version = 1\nid = "t"\ndescription = "t"\n\n[[rules]]\nid = "r"\ndescription = "r"\nlabel = "X"\nregex = ' + json.dumps(r["regex"]) + "\n")
    q = subprocess.run([R, "--only-files", "-f", p, "scan"], input=b"x\n", capture_output=True)
    if q.returncode != 0: bad.append((r["id"], q.stderr.decode()[:200]))
json.dump(bad, open(sys.argv[3], "w"), indent=1)
print(len(bad), "regexes rejected")
for b in bad[:8]: print(b)
