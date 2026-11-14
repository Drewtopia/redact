"""Built-in candidate families: write a trial pack from Betterleaks v1.10.1
regexes, then count matches on an ordinary-text corpus (false hits).

Usage: python candidates.py <v1.toml> <redact> <corpus-file> <out.json>
"""
import json, os, re, subprocess, sys, tomllib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe import translate, flags_of

# rank, family, target pack, proposed redact rule id, Betterleaks rule ids
FAMILIES = [
    (1, "npm access tokens", "npm", "npm-token", ["npm-access-token"]),
    (2, "GitLab token family (beyond glpat-)", "credentials", "gitlab-token (widen)", [
        "gitlab-pat-routable-versioned", "gitlab-runner-authentication-token",
        "gitlab-runner-authentication-token-routable", "gitlab-cicd-job-token",
        "gitlab-deploy-token", "gitlab-feed-token", "gitlab-ptt", "gitlab-rrt",
        "gitlab-oauth-app-secret", "gitlab-kubernetes-agent-token", "gitlab-incoming-mail-token",
        "gitlab-feature-flag-client-token", "gitlab-scim-token", "gitlab-session-cookie"]),
    (3, "Slack and Teams webhooks; Slack app, config and session tokens", "credentials", "chat-webhook + vendor-key (widen)", [
        "slack-webhook-url", "microsoft-teams-webhook", "slack-app-token", "slack-config-access-token",
        "slack-config-refresh-token", "slack-session-token", "slack-session-cookie"]),
    (4, "AWS key ids beyond AKIA/ASIA, and Bedrock API keys", "credentials", "aws-key (widen) + aws-bedrock-key", [
        "aws-access-token", "aws-amazon-bedrock-api-key-long-lived", "aws-amazon-bedrock-api-key-short-lived"]),
    (5, "Docker Hub tokens and Swarm tokens", "credentials", "dockerhub-token + docker-swarm-token", [
        "dockerhub-personal-access-token", "dockerhub-organization-access-token",
        "docker-swarm-join-token", "docker-swarm-unlock-key"]),
    (6, "PyPI upload tokens", "credentials", "pypi-token", ["pypi-upload-token"]),
    (7, "HashiCorp Vault and Terraform Cloud tokens", "credentials", "vault-token + terraform-token", [
        "vault-service-token", "vault-batch-token", "hashicorp-tf-api-token"]),
    (8, "Hugging Face tokens", "credentials", "huggingface-token", [
        "huggingface-access-token", "huggingface-organization-api-token"]),
    (9, "Tailscale API keys", "credentials", "tailscale-key", ["tailscale-api-key.1"]),
    (10, "Grafana tokens", "credentials", "grafana-token", [
        "grafana-api-key", "grafana-cloud-api-token", "grafana-service-account-token"]),
    (11, "Vercel tokens", "credentials", "vercel-token", [
        "vercel-personal-access-token", "vercel-integration-token", "vercel-app-access-token",
        "vercel-app-refresh-token", "vercel-ai-gateway-key"]),
    (12, "Supabase keys", "credentials", "supabase-key", [
        "supabase-management-token", "supabase-project-api-key"]),
    (13, "DigitalOcean tokens", "credentials", "digitalocean-token", [
        "digitalocean-pat", "digitalocean-access-token", "digitalocean-refresh-token"]),
    (14, "Cloudflare API tokens", "credentials", "cloudflare-token", [
        "cloudflare-api-key.2", "cloudflare-origin-ca-key"]),
    (15, "Sentry tokens", "credentials", "sentry-token", ["sentry-org-token", "sentry-user-token"]),
    (16, "AI provider keys not yet in ai-key", "credentials", "ai-key (widen)", [
        "perplexity-api-key", "nvidia-api-key", "cerebras-api-key", "replicate-api-token",
        "togetherai-api-key", "llama-cloud-api-key.1", "langchain-langsmith-personal-access-token",
        "langchain-langsmith-service-key", "pinecone-api-key.2", "cartesia-api-key.1",
        "weights-and-biases-api-key-v1", "gcp-gemini-api"]),
    (17, "Atlassian and Bitbucket Data Center tokens", "credentials", "atlassian-token", [
        "atlassian-api-token", "bitbucket-data-center-token"]),
    (18, "SendGrid API keys", "credentials", "sendgrid-key", ["sendgrid-api-token"]),
    (19, "Databricks tokens", "credentials", "databricks-token", ["databricks-api-token"]),
    (20, "Shopify tokens", "credentials", "shopify-token", [
        "shopify-access-token", "shopify-custom-access-token", "shopify-private-app-access-token",
        "shopify-shared-secret"]),
    (21, "CI service tokens (Buildkite, CircleCI)", "credentials", "ci-token", [
        "buildkite-user-access-token", "buildkite-service-token", "circleci-personal-token"]),
    (22, "1Password service-account and secret keys", "credentials", "onepassword-key", [
        "1password-secret-key", "1password-service-account-token"]),
    (23, "age secret keys", "credentials", "age-key", ["age-secret-key"]),
    (24, "Linear, Notion and Postman keys", "credentials", "linear-key, notion-token, postman-key", [
        "linear-api-key", "notion-api-token", "postman-api-token"]),
    (25, "PlanetScale and Neon database tokens", "credentials", "planetscale-token, neon-key", [
        "planetscale-api-token", "planetscale-oauth-token", "planetscale-password", "neon-api-key"]),
    (26, "Fly.io, Heroku v2, Render, Deno, Doppler, Pulumi deploy tokens", "credentials", "deploy-token", [
        "flyio-access-token", "heroku-api-key-v2", "render-api-key", "deno-account-token",
        "doppler-api-token", "pulumi-api-token"]),
    (27, "Package registry keys (RubyGems, Clojars, NuGet)", "credentials", "registry-token", [
        "rubygems-api-token", "clojars-api-token", "nuget-api-key"]),
    (28, "OpenShift user tokens", "credentials", "openshift-token", ["openshift-user-token"]),
    (29, "PostHog personal keys", "credentials", "posthog-key", ["posthog-personal-api-key"]),
    (30, "Elastic Cloud and Datastax Astra keys", "credentials", "elastic-key, astra-token", [
        "elastic-cloud-api-key", "datastax-astra-application-token"]),
]


def main():
    rules = {r["id"]: r for r in tomllib.load(open(sys.argv[1], "rb"))["rules"]}
    redact, corpus, out = sys.argv[2], sys.argv[3], sys.argv[4]
    lines = ['schema_version = 1', 'id = "trial"', 'description = "trial"', ""]
    for _, _, _, _, ids in FAMILIES:
        for rid in ids:
            rx = rules[rid]["regex"].replace(r"[\w-]{50,1000}", r"[A-Za-z0-9_-]{50,}") \
                                    .replace(r"[\w-]{138,300}", r"[A-Za-z0-9_-]{138,}")
            lines += ["[[rules]]", f"id = {json.dumps(rid)}", 'description = "t"', 'label = "X"',
                      f"regex = {json.dumps(rx)}", ""]
            p, fl = flags_of(translate(rx))
            if re.compile(p, fl).groups:
                lines.insert(len(lines) - 1, "secretGroup = 1")
    pack = os.path.join(os.path.dirname(os.path.abspath(out)), "trial.toml")
    open(pack, "w").write("\n".join(lines))
    with open(corpus, "rb") as f:
        p = subprocess.run([redact, "--only-files", "-f", pack, "scan", "--json"], stdin=f,
                           capture_output=True)
    if p.returncode:
        sys.exit(p.stderr.decode()[:500])
    hits = {}
    for sp in json.loads(p.stdout):
        hits[sp["rule"]] = hits.get(sp["rule"], 0) + 1
    res = [{"rank": r, "family": fam, "pack": pk, "rule_id": new, "betterleaks": ids,
            "corpus_hits": {i: hits.get(i, 0) for i in ids if hits.get(i)}}
           for r, fam, pk, new, ids in FAMILIES]
    json.dump(res, open(out, "w"), indent=1)
    print("corpus hits:", {k: v for k, v in hits.items()})


if __name__ == "__main__":
    main()
