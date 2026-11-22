# gjallar-opa

Gjallar's policies as plain [Rego](https://www.openpolicyagent.org/), so you
can use them with **OPA, Conftest or Gatekeeper**: no Gjallar server and no
particular admission controller required.

| Path | What |
|---|---|
| `policy/posture/gj.rego` | Posture checks **GJ-001 … GJ-009** for any Kubernetes manifest (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob). The same checks Gjallar runs on live workloads |
| `policy/scan/gate.rego` | CI gate over `gjallar scan <image> --json`: fail at or above a risk band, and on known-exploited CVEs; denied licences warn |
| `gatekeeper/` | OPA Gatekeeper `ConstraintTemplate` (`GjallarBaseline`) with the same nine checks, a `dryrun` constraint, `exemptChecks` for recorded opt-outs, and a `gator verify` suite |
| `examples/` | `ci.sh` (Conftest in a pipeline), `gate.yaml` (settings) |

Every message says what was found and why (Gjallar's own reasons), for example:

```
CVE-2026-111497 in libbrotli1 1.0.9-2+b6: risk 78 (urgent) - known exploited (CISA KEV); fix available
GJ-007 medium Deployment/web container web: image nginx is not pinned (latest or no tag); the same name can change underneath you
```

## Use

```bash
# shift-left: manifests in a repo
conftest test k8s/*.yaml -p policy/posture --namespace gjallar.posture

# CI gate on an image (no server: Syft + Grype run locally)
gjallar scan registry.example.com/app:1.4 --json > scan.json
conftest test scan.json -p policy/scan --namespace gjallar.scan --data examples/gate.yaml

# plain OPA
opa eval -d policy/posture -i pod.json 'data.gjallar.posture.deny'
```

The gate leaves the decision with you: `fail_on` and `fail_on_kev` set where
the line is, and findings you have accepted in Gjallar (VEX) never fail it.

## Test

```bash
opa test policy -v      # 8 tests: every GJ check, registry-port tags, CronJobs, gate thresholds, accepted findings
gator verify gatekeeper # Gatekeeper's own engine: allowed, all nine checks, messages, exemptions
```

Verified 2026-11-22 with OPA 1.4.2, and the gate against a real
`gjallar scan nginx:1.27 --json` (790 findings → 1 urgent KEV finding fails the gate).

Kyverno users: equivalent policies ship in
[gjallar-helm](https://github.com/heimdallr-dev/gjallar-helm/tree/main/policies/kyverno).
Gatekeeper users: `kubectl apply -f gatekeeper/template.yaml -f gatekeeper/constraint.yaml`
(starts in `dryrun`; move to `warn`, then `deny`, when the results look right).

Apache-2.0.
