"""Join probe results, hand checks and candidate families into Markdown tables.

Usage: python report.py <v1.toml> <v1.tsv> <cand.json> <v1v2.tsv> <out.md>
"""
import csv, json, sys, tomllib

# Composite secrets the automatic probe scored too strictly; checked by hand
# (hand.py): the secret part is hidden, the rest of the match is not.
HAND = {
    "mongodb-connection-string": ("covered", "url-password hides the password; user and host stay"),
    "gcp-service-account": ("covered", "named-secret-quoted hides private_key"),
    "azure-servicebus-connection-string": ("covered", "azure-storage-key hides SharedAccessKey="),
    "jwt": ("covered", "jwt hides the eyJ…eyJ… form every real JWT has; Betterleaks also takes any ey…"),
    "gcp-application-default-credentials": ("covered", "google-oauth-secret and google-refresh-token hide both secrets"),
    "kubernetes-secret-yaml": ("covered", "kubernetes:secret-data-yaml hides Secret data values"),
    "gitlab-incoming-mail-address-token": ("covered", "identity:email hides the whole reply address"),
    "sidekiq-sensitive-url": ("partly", "url-password hides the password half of user:password"),
}

# Missed rules that match an identifier, host or public key, not a secret.
IDENT = {
    "artifactory-jfrog-url", "auth0-domain.1", "ebay-client-id", "lark-app-id",
    "langfuse-public-key.1", "mongodb-atlas-service-account-id", "posthog-project-api-key",
    "ramp-client-id", "razorpay-key-id.1", "salesforce-instance-url.1", "snowflake-account-host.1",
    "supabase-project-url", "tableau-server-host.1", "upstash-redis-rest-url.1",
    "aikido-client-id", "alibaba-access-key-id", "devcycle-client-sdk-key", "devcycle-mobile-sdk-key",
}

# Missed shape rules whose shape alone is too loose for a built-in rule.
IMPORT_SHAPE = {
    "twilio-api-key": "SK + 32 hex, no left boundary",
    "octopus-deploy-api-key": "API- + 26 capitals: ordinary-looking",
    "clickhouse-cloud-api-secret-key": "4b1d + 38: short hex-like prefix",
    "artifactory-reference-token": "cmVmd + 59: base64 of 'ref', appears in ordinary base64",
    "facebook-access-token": "digits + | or % + 27-40: URL-encoded query strings match",
    "facebook-page-access-token": "EAA + one letter: short prefix, relies on entropy 4.0",
    "square-access-token": "EAAA branch is a short prefix shared with Facebook tokens",
    "exoscale-api-key": "EXO + 24-30: short capital prefix",
    "brave-search-api-key": "BSA + 24-40: short capital prefix",
    "resend-api-key.1": "re_ + 8 + _ + 24: short prefix",
    "alibaba-sts-access-key-id": "STS. + 16-64: short prefix",
    "devin-service-user-token": "cog_ + 52 base32: short prefix",
    "salesforce-access-token.1": "00 + 13 + ! + 80-260: two-digit prefix",
    "tableau-personal-access-token.1": "base64 == : 32: no prefix",
    "azure-ad-client-secret": "redact already has entra-client-secret; see the Entra note",
    "airtable-personnal-access-token": "pat + 14 + . + 64 hex: `pat` is an ordinary word; needs the dot-and-hex shape kept whole",
}

CANDIDATE_RANK = {}
# From the v1v2 normalised diff: changes beyond the end-delimiter group.
SUBSTANTIVE = {"generic-api-key", "generic-password", "mapbox-api-token", "tailscale-api-key.1"}


def main():
    v1 = {r["id"]: r for r in tomllib.load(open(sys.argv[1], "rb"))["rules"]}
    rows = list(csv.DictReader(open(sys.argv[2]), delimiter="\t"))
    cand = json.load(open(sys.argv[3]))
    diff = {r["id"]: r for r in csv.DictReader(open(sys.argv[4]), delimiter="\t")}
    for c in cand:
        for rid in c["betterleaks"]:
            CANDIDATE_RANK[rid] = c
    # Gemini keys ride with the ai-key family.
    out, counts = [], {}
    for row in rows:
        rid = row["id"]
        shape, named, kind = row["shape"], row["named"], row["kind"]
        note = ""
        if rid in HAND:
            shape, note = HAND[rid]
        if rid == "pkcs12-file":
            cls, note = "n/a", "matches file paths, not text"
        elif shape == "covered":
            cls = "covered"
            note = note or row["redact_rules"].replace("credentials:", "")
        elif rid in CANDIDATE_RANK:
            c = CANDIDATE_RANK[rid]
            cls = f"built in #{c['rank']}"
            note = f"`{c['pack']}`: {c['rule_id']}"
        elif shape == "partly" and kind == "prefix" and "(?:[ \\t\\w.-]{0,20})" not in v1[rid].get("regex", ""):
            cls = "partly: widen"
            note = note or row["redact_rules"].replace("credentials:", "")
        elif rid in IDENT:
            cls = "not a secret"
            note = "identifier, host or public key"
        elif rid in IMPORT_SHAPE:
            cls = "import only"
            note = IMPORT_SHAPE[rid]
        elif kind in ("context", "none") or rid.startswith(("generic-", "new-relic-", "ovh-")) \
                or "(?:[ \\t\\w.-]{0,20})" in v1[rid].get("regex", ""):
            cls = "import only"
            note = note or "vendor keyword before the value" + (
                "; hidden when the name says key/token/secret" if named == "covered" else "")
            if shape == "partly":
                note += " (hidden in some probes, when the sampled name said key or token)"
        else:
            cls = "built in, later"
            note = "distinctive prefix; service less common in terminal output"
        counts[cls.split(" #")[0]] = counts.get(cls.split(" #")[0], 0) + 1
        d = diff.get(rid, {}).get("status", "")
        d = {"differs": "end delimiter only", "same": "same"}.get(d, d)
        if rid in SUBSTANTIVE:
            d = "**regex changed**"
        out.append((rid, shape, named, cls, note, d))
    with open(sys.argv[5], "w") as f:
        f.write("| Betterleaks rule | Bare / log / JSON / table | Behind a secret name | Class | Note | v2 main |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in out:
            f.write("| `" + r[0] + "` | " + " | ".join(r[1:]) + " |\n")
    print(json.dumps(counts, indent=1))
    by = {}
    for r in out:
        by.setdefault(r[3], []).append(r[0])
    import collections; print("verdicts", collections.Counter(r[1] for r in out))
    print({k: len(v) for k, v in by.items() if k.startswith("built in #")})
    print("later:", " ".join(by.get("built in, later", [])))
    print("partly-widen:", " ".join(by.get("partly: widen", [])))


if __name__ == "__main__":
    main()
