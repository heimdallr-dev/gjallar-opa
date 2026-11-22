package gjallar.scan_test

import rego.v1

import data.gjallar.scan

report := {
	"findings": [
		{
			"vuln_id": "CVE-2023-4863", "package": "libwebp7", "version": "1.2.4", "kev": true, "state": "open",
			"risk": {"value": 88, "band": "urgent", "reasons": ["known exploited (CISA KEV)", "fix available"]},
		},
		{
			"vuln_id": "CVE-2099-0001", "package": "openssl", "version": "3.0.11", "kev": false, "state": "open",
			"risk": {"value": 20, "band": "medium", "reasons": []},
		},
		{
			"vuln_id": "CVE-2024-1", "package": "zlib", "version": "1", "kev": true, "state": "accepted",
			"risk": {"value": 30, "band": "medium", "reasons": []},
		},
	],
	"licenses": [{"package": "readline", "version": "8.2", "license": "GPL-3.0-only", "verdict": "denied"}],
}

test_default_fails_on_urgent_only if {
	msgs := scan.deny with input as report
	count(msgs) == 1
	some m in msgs
	contains(m, "CVE-2023-4863")
	contains(m, "known exploited")
}

test_accepted_findings_never_fail if {
	not any_mentions("CVE-2024-1") with input as report with data.gjallar_gate.fail_on as "low"
}

any_mentions(id) if {
	some m in scan.deny
	contains(m, id)
}

test_threshold_medium if count(scan.deny) == 2 with input as report with data.gjallar_gate.fail_on as "medium"

test_licences_warn_not_fail if count(scan.warn) == 1 with input as report
