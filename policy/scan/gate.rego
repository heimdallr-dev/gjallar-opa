# CI gate over `gjallar scan <image> --json`: fail when an open finding is at
# or above a risk band, or (optionally) is known exploited. Every message says
# why, using Gjallar's own reasons.
# Settings (data.gjallar_gate, e.g. conftest --data gate.yaml): fail_on (urgent|high|medium|low, default urgent), fail_on_kev (default true).
package gjallar.scan

import rego.v1

rank := {"low": 0, "medium": 1, "high": 2, "urgent": 3}

default fail_on := "urgent"

fail_on := data.gjallar_gate.fail_on

default fail_on_kev := true

fail_on_kev := data.gjallar_gate.fail_on_kev

open_findings contains f if {
	some f in input.findings
	object.get(f, "state", "open") == "open"
}

deny contains msg if {
	some f in open_findings
	rank[f.risk.band] >= rank[fail_on]
	msg := sprintf("%s in %s %s: risk %d (%s) - %s", [f.vuln_id, f["package"], f.version, f.risk.value, f.risk.band, concat("; ", object.get(f.risk, "reasons", []))])
}

deny contains msg if {
	fail_on_kev
	some f in open_findings
	f.kev == true
	rank[f.risk.band] < rank[fail_on]
	msg := sprintf("%s in %s %s is known exploited (CISA KEV), risk %d (%s) - %s", [f.vuln_id, f["package"], f.version, f.risk.value, f.risk.band, concat("; ", object.get(f.risk, "reasons", []))])
}

warn contains msg if {
	some l in input.licenses
	l.verdict == "denied"
	msg := sprintf("licence %s on %s %s is denied by policy", [l.license, l["package"], l.version])
}
