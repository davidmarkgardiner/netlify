---
title: "Pod Security Standards"
date: 2023-05-08T10:27:23+01:00
# draft: true
author: "DavidGardiner"
tags:
  - k8s
  - pod-security
  - aks
  - kubernetes
image: /images/post.jpg

---


<!-- # Pod Security Standards -->

---


[pod-security-admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)

[pod-security-standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

[migrate-from-psp](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)

## Pod Security Standards

The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards let you define how you want to restrict the behavior of pods in a clear, consistent fashion.

Kubernetes offers a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when pods are created.

```
# Privileged
Unrestricted policy, providing the widest possible level of permissions. This policy allows for known privilege escalations.

# Baseline
Minimally restrictive policy which prevents known privilege escalations. Allows the default (minimally specified) Pod configuration.

# Restricted
Heavily restricted policy, following current Pod hardening best practices

```

```
# enforce
Policy violations will cause the pod to be rejected.

# audit
Policy violations will trigger the addition of an audit annotation to the event recorded in the audit log, but are otherwise allowed.

# warn
Policy violations will trigger a user-facing warning, but are otherwise allowed.

```

```
# The per-mode level label indicates which policy level to apply for the mode.
#
# MODE must be one of `enforce`, `audit`, or `warn`.
# LEVEL must be one of `privileged`, `baseline`, or `restricted`.

pod-security.kubernetes.io/<MODE>: <LEVEL>

# Optional: per-mode version label that can be used to pin the policy to the
# version that shipped with a given Kubernetes minor version (for example v1.26).
#
# MODE must be one of `enforce`, `audit`, or `warn`.
# VERSION must be a valid Kubernetes minor version, or `latest`.

pod-security.kubernetes.io/<MODE>-version: <VERSION>

```

Setting labels  will allow you to enforce security pod policies that are also controlled via am18 (azurepolicy)

labels  `enforce=baseline` and `enforce=resticted`

I would advise using `restricted` where possible and `baseline` as standard.

for production its recommended using audit for a week or more to check for any effected workloads

labels  `audit=baseline` and `audit=resticted`

For detailed restrictions please see: [pod-security-standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

```
Example usage:

# Ensure to check warnings before enforcing this policy

k label ns < namespace > pod-security.kubernetes.io/warn=baseline
k label ns < namespace > pod-security.kubernetes.io/warn=restricted

# We advise you to send logs to audit and monitor to check if anything is being blocked.

k label ns < namespace > pod-security.kubernetes.io/audit=baseline
k label ns < namespace > pod-security.kubernetes.io/audit=restricted

# After you have remediated any warnings you can enforce settings.

k label ns < namespace > pod-security.kubernetes.io/enforce=baseline
k label ns < namespace > pod-security.kubernetes.io/enforce=restricted

```

```
# Apply using script
#!/bin/bash

# Get a list of all namespaces in the cluster
namespaces=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}')

# Apply the label to each namespace
for namespace in $namespaces
do
  kubectl label namespace $namespace pod-security.kubernetes.io/enforce=baseline
done

```

<!-- ### How to comply with enforced Azure policy -->
<!-- 
for further guidance please see [pod-security-admission](notion://www.notion.so/podsecurityadmission.html)

```

# `pod-security.kubernetes.io/enforce=baseline`

AKSAllowedProcMountType  | Pod containers can only use allowed ProcMountTypes in a Kubernetes cluster.
AKSContainerDisSysA      | Limit pod HostPath volume mounts to the allowed host paths in a Kubernetes Cluster.
AKSForSysInt             | Containers should not use forbidden sysctl interfaces in a Kubernetes cluster
AKSContainerNP           | Do not allow privileged containers creation in a Kubernetes cluste
AKSAppArmor              | Containers should only use allowed AppArmor profiles in a Kubernetes cluster.
AKSAllowedHostPaths      | AKS Clusters should Limit pod HostPath volume mounts to the allowed host paths in Cluster
AKSAllowedSeccompProfile | Pod containers can only use allowed seccomp profiles in a Kubernetes cluster
AKSNoShHostProcHIPC      | Block pod containers from sharing the host process ID namespace and host IPC namespace in a Kubernetes cluster

# `pod-security.kubernetes.io/enforce=restricted`

AKSContainerNPEsc        | Do not allow containers to run with privilege escalation to root in a Kubernetes cluster
AKSAllowedVolumeTypes    | Pods can only use allowed volume types in a Kubernetes cluster.
AKSRORootFiles           | Run containers with a read only root file system to protect from changes at run-time with malicious binaries being added to PATH in a Kubernetes cluster

```

### Additional policys that will be set using label that are NOT currently enforced using azure policy

```
# Baseline
Kubernetes cluster containers should only use allowed capabilities
  - Adding additional capabilities beyond those listed below must be disallowed.

Kubernetes cluster services should listen only on allowed ports
  - HostPorts should be disallowed entirely (recommended) or restricted to a known list

Kubernetes cluster pods and containers should only use allowed SELinux options
  - Setting the SELinux type is restricted, and setting a custom SELinux user or role option is forbidden.

# Resticted
Kubernetes cluster pods and containers should only run with approved user and group IDs
  - Containers must not set runAsUser to 0

``` -->

