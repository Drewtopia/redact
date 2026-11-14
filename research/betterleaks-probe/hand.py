"""Hand checks: realistic or composite shapes the generator scores badly.
Usage: python hand.py <redact> <config>"""
import json, random, string, subprocess, sys
R, CFG = sys.argv[1], sys.argv[2]
rng = random.Random(7)
def rnd(n, cs=string.ascii_letters + string.digits): return "".join(rng.choice(cs) for _ in range(n))
pw = rnd(20); key = rnd(64); sa = rnd(40)
cases = [
 ("jwt eyJ", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi" + rnd(20) + "." + rnd(43), None),
 ("mongodb-connection-string", f"mongodb+srv://appuser:{pw}@cluster0.ab1cd.mongodb.net/db", pw),
 ("gcp-service-account", '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\n' + key + '\\n-----END PRIVATE KEY-----\\n", "client_email": "x@p.iam.gserviceaccount.com"}', key),
 ("gcp-application-default-credentials", '{"client_id": "1.apps.googleusercontent.com", "client_secret": "GOCSPX-' + rnd(28) + '", "refresh_token": "1//0' + rnd(60) + '", "type": "authorized_user"}', None),
 ("azure-servicebus-connection-string", f"Endpoint=sb://ns1.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={rnd(43)}=", None),
 ("sidekiq-sensitive-url", f"https://{rnd(8,'0123456789abcdef')}:{rnd(8,'0123456789abcdef')}@gems.contribsys.com/", None),
 ("slack-webhook-url", "https://hooks.slack.com/services/T0" + rnd(9) + "/B0" + rnd(9) + "/" + rnd(24), None),
 ("aws AKIA", "AKIA" + rnd(16, string.ascii_uppercase + "234567"), None),
 ("entra 3+digit+Q~", rnd(3) + "8Q~" + rnd(34), None),
 ("dockerhub pat", "dckr_pat_" + rnd(27), None),
]
for name, text, secret in cases:
    if name.startswith("azure"):
        secret = text.split("SharedAccessKey=")[1]
    secret = secret or text
    out = json.loads(subprocess.run([R, "-c", CFG, "scan", "--json"], input=(text+"\n").encode(), capture_output=True).stdout)
    s = text.find(secret); cov = [False]*len(secret); rules=set()
    for sp in out:
        lo, hi = max(sp["start"], s), min(sp["end"], s+len(secret))
        if lo < hi:
            rules.add(sp["rule"]); cov[lo-s:hi-s] = [True]*(hi-lo)
    print(f"{name}: {sum(cov)}/{len(secret)} bytes hidden by {sorted(rules)}")
