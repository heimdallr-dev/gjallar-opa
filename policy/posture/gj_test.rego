package gjallar.posture_test

import rego.v1

import data.gjallar.posture

hardened := {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}, "spec": {"template": {"spec": {
	"securityContext": {"runAsNonRoot": true},
	"containers": [{
		"name": "web", "image": "harbor.local:5000/shop/web:1.4",
		"securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
		"resources": {"limits": {"cpu": "1", "memory": "256Mi"}},
	}],
}}}}

test_hardened_passes if count(posture.deny) == 0 with input as hardened

risky := {"kind": "Pod", "metadata": {"name": "bad"}, "spec": {
	"hostNetwork": true,
	"volumes": [{"name": "root", "hostPath": {"path": "/"}}],
	"containers": [{
		"name": "c", "image": "nginx",
		"securityContext": {"privileged": true, "capabilities": {"add": ["SYS_ADMIN", "NET_BIND_SERVICE"]}},
	}],
}}

test_risky_hits_every_check if {
	ids := {substring(m, 0, 6) | some m in posture.deny} with input as risky
	ids == {"GJ-001", "GJ-002", "GJ-003", "GJ-004", "GJ-005", "GJ-006", "GJ-007", "GJ-008", "GJ-009"}
}

test_registry_port_is_not_a_tag if {
	posture.mutable("harbor.local:5000/app")
	not posture.mutable("harbor.local:5000/app:1.0")
	not posture.mutable("app@sha256:abc")
	posture.mutable("app:latest")
}

test_cronjob_containers_found if {
	cj := {"kind": "CronJob", "metadata": {"name": "nightly"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "j", "image": "busybox:1.36", "securityContext": {"privileged": true}}]}}}}}}
	some m in posture.deny with input as cj
	startswith(m, "GJ-001")
}
