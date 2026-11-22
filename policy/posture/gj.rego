# Gjallar posture checks GJ-001..GJ-009 as plain Rego, for Conftest, OPA and
# Gatekeeper users. Same checks Gjallar runs on live workloads
# (internal/domain/policy.go), so CI and the cluster agree.
# Input: one Kubernetes object (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet).
package gjallar.posture

import rego.v1

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers

containers contains c if some c in pod_spec.initContainers

name := sprintf("%s/%s", [input.kind, input.metadata.name])

dangerous_caps := {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}

# runAsNonRoot: the container's setting wins over the pod-level one.
runs_as_non_root(c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(c) if {
	not c.securityContext.runAsNonRoot == false
	pod_spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("GJ-001 critical %s container %s: privileged: true gives it full access to the node", [name, c.name])
}

deny contains msg if {
	some ns in ["hostNetwork", "hostPID"]
	pod_spec[ns] == true
	msg := sprintf("GJ-002 high %s: %s shares the node's namespace with the pod", [name, ns])
}

deny contains msg if {
	some v in pod_spec.volumes
	v.hostPath
	msg := sprintf("GJ-003 high %s: volume %s mounts a hostPath (node filesystem)", [name, v.name])
}

deny contains msg if {
	some c in containers
	not runs_as_non_root(c)
	msg := sprintf("GJ-004 medium %s container %s: runAsNonRoot is not set, so it may run as root", [name, c.name])
}

deny contains msg if {
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("GJ-005 medium %s container %s: allowPrivilegeEscalation is not false", [name, c.name])
}

deny contains msg if {
	some c in containers
	not c.resources.limits
	msg := sprintf("GJ-006 low %s container %s: no CPU/memory limits; one runaway container can starve the node", [name, c.name])
}

deny contains msg if {
	some c in containers
	mutable(c.image)
	msg := sprintf("GJ-007 medium %s container %s: image %s is not pinned (latest or no tag); the same name can change underneath you", [name, c.name, c.image])
}

deny contains msg if {
	some c in containers
	some cap in c.securityContext.capabilities.add
	upper(cap) in dangerous_caps
	msg := sprintf("GJ-008 high %s container %s: adds capability %s", [name, c.name, cap])
}

deny contains msg if {
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("GJ-009 low %s container %s: readOnlyRootFilesystem is not true", [name, c.name])
}

mutable(image) if endswith(image, ":latest")

# No tag after the last "/" (a registry port like host:5000/app is not a tag) and no digest.
mutable(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	not contains(parts[count(parts) - 1], ":")
}
