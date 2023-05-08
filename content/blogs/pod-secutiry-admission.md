---
title: "Pod Secutiry Admission"
date: 2023-05-08T10:34:38+01:00
# draft: true
author: "DavidGardiner"
tags:
  - k8s
  - pod-security
  - aks
image: /images/post.jpg
---

# Pod Security Admission

---

<!-- ## title: Pod Security Admission
layout: article
keywords: AKS, containers, kubernetes, security, Pod Security Admission
description: The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards let you define how you want to restrict the behavior of pods in a clear, consistent fashion. -->

[pod-security-admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)

[pod-security-standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

[migrate-from-psp](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)

## Pod Security Admission has replaced Pod Security Policy (PSP)

Starting from Kubernetes version 1.21, Pod Security Policies (PSP) were officially deprecated and replaced with Pod Security Admission (PSA). PSA implements the Pod Security Standards (PSS), a set of policies describing various security-related characteristics of workloads in a Kubernetes cluster. As of version 1.25, PSA is now a stable feature, and PSP has been completely removed.

## Pod Security Admission

The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards allow you to clearly and consistently define how to restrict the behavior of Pods.

Kubernetes provides a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when creating Pods.

To comply with security best practices, we strongly advise setting the following labels on your cluster. Azure policies will enforce these labels in future iterations.

For further instructions, please see pod-security-standards.

```
enforce - Policy violations will cause the pod to be rejected.
audit	- Policy violations will trigger the addition of an audit annotation to the event recorded in the audit log, but are otherwise allowed.
warn	- Policy violations will trigger a user-facing warning, but are otherwise allowed.

Privileged	 - Unrestricted policy, providing the widest possible level of permissions. This policy allows for known privilege escalations.
Baseline	 - Minimally restrictive policy which prevents known privilege escalations. Allows the default (minimally specified) Pod configuration.
Restricted	 - Heavily restricted policy, following current Pod hardening best practices

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

## PSP.yaml

(example only, this was previously recommended for use. REMOVED in AKS 1.25)

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: recommended-psp
spec:
  allowedHostPaths:
  - pathPrefix: /var/log
    readOnly: false
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  allowedCSIDrivers:
    - name: blob.csi.azure.com
    - name: disk.csi.azure.com
    - name: file.csi.azure.com
  allowedCapabilities:
  - AUDIT_WRITE
  - CHOWN
  - DAC_OVERRIDE
  - FOWNER
  - FSETID
  - KILL
  - SETGID
  - SETUID
  - SETPCAP
  - NET_BIND_SERVICE
  - SYS_CHROOT
  - SETFCAP
  volumes:
  - configMap
  - downwardAPI
  - emptyDir
  - persistentVolumeClaim
  - secret
  - projected
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
    - min: 1
      max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
    - min: 1
      max: 65535

```

## deployment.yaml that is NOW recommended for use.

This is a Kubernetes Pod Security Admission configuration file for a container called "podinfod". It specifies security settings such as not allowing privilege escalation, running as a non-root user, and dropping all capabilities. 

This security context:

- Prevents privilege escalation by setting allowPrivilegeEscalation to false.
- Prevents service account token mounting by setting to false.
- Drops all Linux capabilities by setting capabilities to drop all.
- Makes the root file system read-only by setting readOnlyRootFilesystem to true.
- Runs the container as a non-root user by setting runAsNonRoot to true and runAsUser to a non-root user ID (in this example, 1000).
- Block pod containers from sharing the host process ID namespace and host IPC namespace in a Kubernetes cluster

```
        app.kubernetes.io/name: podinfo-kustomize
    spec:
      hostIPC: false
      hostPID: false
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      automountServiceAccountToken: false
      containers:
        - name: podinfod
          image: poc-container-registry.ubs.net/cr-demo/stefanprodan/podinfo:6.1.2
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
            capabilities:
              drop:
                - all
          imagePullPolicy: IfNotPresent

```

##To see current constrainttemplates

```
kubectl get constrainttemplate

NAME                                     AGE
...
k8sazurev2containerallowedimages         5d17h
k8sazurev2noprivilege                    5d17h
k8sazurev2volumetypes                    5d17h
k8sazurev3allowedcapabilities            5d17h
k8sazurev3allowedseccomp                 5d17h
k8sazurev3allowedusersgroups             5d17h
k8sazurev3containerlimits                5d17h
k8sazurev3disallowedcapabilities         5d17h
k8sazurev3enforceapparmor                5d17h
k8sazurev3hostfilesystem                 5d17h
k8sazurev3hostnetworkingports            5d17h
k8sazurev3noprivilegeescalation          5d17h
k8sazurev3readonlyrootfilesystem         5d17h
k8sazurev4procmount                      5d17h
...

```

## How to comply with constraints

The simplest way to comply is to set labels as per guidance here: [pod-security-standards](notion://www.notion.so/podsecuritystandards.html)

# AM18 policys to be enforced as DENY using azure Policy

Some background and guidance is provided below.

### readOnlyRootFilesystem

To keep a system secure, it's important to prevent containers from writing to the root file system, which can lead to instability or compromise. Attackers can exploit this to gain elevated privileges and execute arbitrary code on the host machine. However, sometimes a container needs to write to the root file system, such as when it needs to access system-level configuration files or write logs. In these cases, proceed with caution and only allow it when necessary. It's generally recommended to restrict container access to the root file system to minimize the risk of compromise.

```

containers:
- name: podinfod
  image: poc-container-registry.ubs.net/cr-demo/stefanprodan/podinfo:6.1.2 # {"$imagepolicy": "demo:podinfo-dev"}
  securityContext:
    readOnlyRootFilesystem: true
  imagePullPolicy: IfNotPresent
  ports:

```

### seccompProfile

We use Seccomp to limit the system calls that containers can make, reducing their potential to perform harmful operations and minimizing the attack surface. Seccomp profiles must be set to an allowed value; both the Unconfined profile and the absence of a profile are prohibited. 

```
Restricted Fields

spec.securityContext.seccompProfile.type
spec.containers[*].securityContext.seccompProfile.type
spec.initContainers[*].securityContext.seccompProfile.type
spec.ephemeralContainers[*].securityContext.seccompProfile.type
Allowed Values

RuntimeDefault
Localhost

```

```
spec:
securityContext:
  # allowPrivilegeEscalation: false
  # readOnlyRootFilesystem: true
  # runAsNonRoot: true
  # runAsUser: 1000
  # capabilities:
  #   drop:
  #     - all
  seccompProfile:
    type: RuntimeDefault

```

### automountServiceAccountToken

In AKS, pods may auto-mount a service token, which is used for authentication and authorization purposes. Service tokens are linked to a service account and are used by Kubernetes to grant permissions to resources in the cluster. AKS assigns a service account by default to each pod for authentication requests made to the Kubernetes API server.

The service account associated with a pod is used to authenticate requests made by the pod to the Kubernetes API server and determine the level of authorization it has. To access certain resources, such as secrets or config maps, the pod needs to be authorized by the service account. By auto-mounting the service token, the pod can authenticate itself with the Kubernetes API server and access the necessary resources. This ensures that the pod functions properly and has the necessary permissions to perform its tasks.

Auto-mounting the service token is an important step in securing the cluster and ensuring that pods have the necessary authentication and authorization to access the resources they need. However, if not properly managed, it can also pose a security risk. An attacker who gains access to a pod with a mounted service account token can potentially use the token to authenticate and gain access to other resources within the cluster.

```
spec:
securityContext:
  # allowPrivilegeEscalation: false
  # readOnlyRootFilesystem: true
  # runAsNonRoot: true
  # runAsUser: 1000
  # capabilities:
  #   drop:
  #     - all
  # seccompProfile:
  #   type: RuntimeDefault
automountServiceAccountToken: false
containers:

```

### allowPrivilegeEscalation

We prevent the creation of privileged containers in a Kubernetes cluster. Privileged containers run with root privileges and have access to all resources on the host machine, including the ability to modify system files and access sensitive data.

```
Privileged Pods disable most security mechanisms and must be disallowed.

Restricted Fields

spec.containers[*].securityContext.privileged
spec.initContainers[*].securityContext.privileged
spec.ephemeralContainers[*].securityContext.privileged

Allowed Values
Undefined/nil
false

```

```
containers:
- name: podinfod
  image: poc-container-registry.ubs.net/cr-demo/stefanprodan/podinfo:6.1.2 # {"$imagepolicy": "demo:podinfo-dev"}
  securityContext:
    allowPrivilegeEscalation: false
    privileged: false
    readOnlyRootFilesystem: true
  imagePullPolicy: IfNotPresent
  ports:

```

## allowPrivilegeEscalation

We prevent privilege escalation in containers, where a process gains more privileges than originally granted. This is a serious security risk, as an attacker who gains control of a container with escalated privileges can potentially compromise the entire system.

```
Privilege escalation (such as via set-user-ID or set-group-ID file mode) should not be allowed.
This is Linux only policy in v1.25+

Restricted Fields

spec.containers[*].securityContext.allowPrivilegeEscalation
spec.initContainers[*].securityContext.allowPrivilegeEscalation
spec.ephemeralContainers[*].securityContext.allowPrivilegeEscalation

Allowed Values
false

```

```
containers:
- name: podinfod
  image: poc-container-registry.ubs.net/cr-demo/stefanprodan/podinfo:6.1.2 # {"$imagepolicy": "demo:podinfo-dev"}
  securityContext:
    allowPrivilegeEscalation: false
    privileged: false
    readOnlyRootFilesystem: true
  imagePullPolicy: IfNotPresent
  ports:

```

### HostIPC/HostPID

In Kubernetes, containers are usually isolated from the host system's processes and IPC namespaces. However, it's possible to enable access to these namespaces by configuring the container's Pod to use the host's process and IPC namespaces. By setting the hostPID field in the Pod's spec section to true, the container running in the Pod will have access to the host's process namespace. This allows the container to interact with processes running on the host system. In addition, by setting the hostIPC field in the Pod's spec section to true, the container running in the Pod will have access to the host's IPC namespace. This enables the container to use shared memory, semaphores, and other interprocess communication mechanisms that are not available within the container's own namespace. However, enabling access to the host's process and IPC namespaces can be a security risk, as it may allow the container to interfere with other processes or containers running on the host system. Therefore, it's generally recommended to avoid using these features unless absolutely necessary.

```
Sharing the host namespaces must be disallowed.

Restricted Fields

spec.hostNetwork
spec.hostPID
spec.hostIPC

Allowed Values
Undefined/nil
false

```

```

app.kubernetes.io/name: podinfo-kustomize
spec:
  hostIPC: false
  hostPID: false
  securityContext:
    # allowPrivilegeEscalation: true

```

### AllowedVolumeTypes

Not covered by pod security standards and must be set on the policy itself.
[https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)

```
The restricted policy only permits the following volume types.

Restricted Fields

spec.volumes[*]
Allowed Values

Every item in the spec.volumes[*] list must set one of the following fields to a non-null value:

spec.volumes[*].configMap
spec.volumes[*].csi
spec.volumes[*].downwardAPI
spec.volumes[*].emptyDir
spec.volumes[*].ephemeral
spec.volumes[*].persistentVolumeClaim
spec.volumes[*].projected
spec.volumes[*].secret

```

```
  containers:
    - name: demo
      image: alpine
  volumes:
  # You set volumes at the Pod level, then mount them into containers inside that Pod
  - name: config
    configMap:
      # Provide the name of the ConfigMap you want to mount.
      name: demo-name
      # An array of keys from the ConfigMap to create as files
      items:

```

The recommended allowedVolumeTypes for Kubernetes depend on the specific requirements of your application and the level of security you want to enforce. However, there are some commonly used volume types that are generally considered safe to use in Kubernetes:

- configMap: Used to store configuration data as key-value pairs. ConfigMaps can be used to store data that is required by the container at runtime, such as environment variables, command-line arguments, and configuration files.
- emptyDir: A temporary volume that is created when a Pod is launched and deleted when the Pod is terminated. This type of volume is useful for storing temporary data that is required by the container during its lifecycle.
- secret: Used to store sensitive data, such as passwords, encryption keys, and API tokens. Secrets are encrypted at rest and can only be accessed by authorized users or applications.
- persistentVolumeClaim: A claim to a persistent storage resource, such as a disk volume, that is managed by Kubernetes. This type of volume is useful for storing data that needs to persist beyond the lifetime of a Pod.
- downwardAPI: Used to expose Pod and container metadata, such as labels, annotations, and environment variables, as files inside the container's filesystem.
- projected: A flexible volume type that can be used to combine multiple volume sources into a single directory tree inside the container's filesystem. The projected volume can include a mix of ConfigMaps, Secrets, and downwardAPI volumes.

Some volume types (e.g. hostPath, nfs, and glusterfs) give access to the host system's filesystem or network, making them less secure. They should only be used when necessary and with caution. It's best to evaluate the security requirements of your application and choose the appropriate volume types that provide necessary functionality without compromising security.

### capabilities: system admin

allowPrivilegeEscalation controls whether a process can gain more privileges than its parent process. This boolean directly controls whether the no_new_privs flag is set on the container process.

allowPrivilegeEscalation is always true when the container is run as privileged or has CAP_SYS_ADMIN.

The duplication of this setting is governed by allowPrivilegeEscalation.

You cannot set `allowPrivilegeEscalation` to false and `capabilities.Add` CAP_SYS_ADMIN

```
Adding additional capabilities beyond those listed below must be disallowed.

Restricted Fields

spec.containers[*].securityContext.capabilities.add
spec.initContainers[*].securityContext.capabilities.add
spec.ephemeralContainers[*].securityContext.capabilities.add

Allowed Values

Undefined/nil
AUDIT_WRITE
CHOWN
DAC_OVERRIDE
FOWNER
FSETID
KILL
MKNOD
NET_BIND_SERVICE
SETFCAP
SETGID
SETPCAP
SETUID
SYS_CHROOT

```

```
containers:
  - name: podinfod
    image: poc-container-registry.ubs.net/cr-demo/stefanprodan/podinfo:6.1.2
    securityContext:
      capabilities:
        add: ["NET_ADMIN", "SYS_TIME"]
        drop: ["CAP_SYS_ADMIN"]

```

### securityContext.sysctls

You can use the `sysctls` field to specify a list of kernel parameters (sysctls) that are forbidden in the container. By default, all sysctls are allowed in the container unless they are explicitly forbidden using the `sysctls` field.

Here are some examples of forbidden sysctl interfaces that you can specify:

```
Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed "safe" subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node.

Restricted Fields

spec.securityContext.sysctls[*].name

Allowed Values
Undefined/nil
kernel.shm_rmid_forced
net.ipv4.ip_local_port_range
net.ipv4.ip_unprivileged_port_start
net.ipv4.tcp_syncookies
net.ipv4.ping_group_range

```

The following sysctls will be forbidden:

- net.ipv4.ip_forward: This disables IP forwarding between network interfaces. It's commonly used in denial-of-service attacks, so it's generally a good idea to forbid it in most cases.
- net.ipv4.conf.all.accept_source_route: This disables source routing, which allows a sender to specify the path that a packet should take through a network. Source routing can be used to bypass security measures, so it's often forbidden in secure environments.
- kernel.shm*: This forbids all shared memory kernel parameters, which can be used to control the behavior of shared memory segments in the container. These sysctls are often forbidden because they can be used to mount denial-of-service attacks.
- kernel.sem: This disables POSIX message queues and semaphore operations. These operations can be used to synchronize access to shared resources, but they can also be used to mount denial-of-service attacks.

It's important to note that forbidding certain sysctl interfaces can break the functionality of certain applications or services that rely on these interfaces.

### AllowedHostPaths

```
HostPath volumes must be forbidden.

Restricted Fields

spec.volumes[*].hostPath
Allowed Values

Undefined/nil

```

Kubernetes enables you to mount a host path as a volume in a container within a pod, which can be helpful in certain scenarios such as when you need to access files or data on the host system. However, this also creates a security risk as it could allow a container to access sensitive data or files on the host system.

To mitigate this security risk, Kubernetes provides the hostPath volume type with a set of AllowedHostPaths fields. This allows you to specify a list of host paths that are permitted to be mounted as volumes in a pod. By default, the AllowedHostPaths field is empty, which means that host path volumes are not permitted.

Some potential allowed paths might be:

for `ubuntu` and `mariner` tls certs

`hostPath: /etc/ssl/certs`

`hostPath: /etc/pki/tls/certs`

### AllowedProcMountType

```
The default /proc masks are set up to reduce attack surface, and should be required.

Restricted Fields

spec.containers[*].securityContext.procMount
spec.initContainers[*].securityContext.procMount
spec.ephemeralContainers[*].securityContext.procMount

Allowed Values
Undefined/nil
Default

```

In Kubernetes, you can increase the security of your cluster by disabling certain proc mount types. The /proc filesystem allows processes to access information about the running system. However, attackers could use some of the information exposed by this filesystem to gain information about the host system or other containers running on the same node.

To disable proc mount types in Kubernetes, update the Azure policy with the procMount field set to Unmasked. This prevents containers in your cluster from accessing the /proc/sys, /proc/sysrq-trigger, and /proc/latency_stats filesystems.

In Kubernetes, there are three different procMountTypes to mount the /proc filesystem into a container:

1. Default: This is the default value for procMount and is used to mount /proc with the default options. This includes read-only access to most files in the filesystem, and write access to some files.
2. Unmasked: This value allows for more privileged access to the /proc filesystem, which can expose sensitive information about the host system or other containers running on the same node. In particular, it allows for write access to the /proc/sys, /proc/sysrq-trigger, and /proc/latency_stats files.
3. None: This value disables the mounting of the /proc filesystem in the container. This can be used to improve the security of the container, but may impact the functionality of some applications or services that rely on the /proc filesystem.

Carefully consider which procMountType to use for your containers based on their specific requirements and the security implications of each option. In general, the Default option is recommended unless there is a specific need for more privileged access to the /proc filesystem, and it's best to avoid using the None option unless necessary.

### appArmor

```
On supported hosts, the runtime/default AppArmor profile is applied by default. The baseline policy should prevent overriding or disabling the default AppArmor profile, or restrict overrides to an allowed set of profiles.

Restricted Fields

metadata.annotations["container.apparmor.security.beta.kubernetes.io/*"]

Allowed Values
Undefined/nil
runtime/default
localhost/*

```

### SELinux

```
Setting the SELinux type is restricted, and setting a custom SELinux user or role option is forbidden.

Restricted Fields

spec.securityContext.seLinuxOptions.type
spec.containers[*].securityContext.seLinuxOptions.type
spec.initContainers[*].securityContext.seLinuxOptions.type
spec.ephemeralContainers[*].securityContext.seLinuxOptions.type

Allowed Values

Undefined/""
container_t
container_init_t
container_kvm_t

Restricted Fields

spec.securityContext.seLinuxOptions.user
spec.containers[*].securityContext.seLinuxOptions.user
spec.initContainers[*].securityContext.seLinuxOptions.user
spec.ephemeralContainers[*].securityContext.seLinuxOptions.user
spec.securityContext.seLinuxOptions.role
spec.containers[*].securityContext.seLinuxOptions.role
spec.initContainers[*].securityContext.seLinuxOptions.role
spec.ephemeralContainers[*].securityContext.seLinuxOptions.role

Allowed Values
Undefined/""

```

### EnforceCSIDriver - Azure

Kubernetes version 1.26 deprecates the in-tree persistent volume types [kubernetes.io/azure-disk](http://kubernetes.io/azure-disk) and [kubernetes.io/azure-file](http://kubernetes.io/azure-file), which will no longer be supported. The corresponding CSI drivers [disks.csi.azure.com](http://disks.csi.azure.com/) and [file.csi.azure.com](http://file.csi.azure.com/) should be used instead. Although removing the deprecated drivers is not planned, you should migrate to the CSI drivers.

Some clusters still use the deprecated `azureFile` volume type, which has been deprecated since version 1.22. However, this type cannot be disabled without also disabling the `kubernetes.io` type. The policy is currently on/off and cannot be used flexibly yet. This policy is intended to help with the transition, not security. We recommend leaving it in audit mode only until after the 1.26 release, at which point we can move to deny mode. We will alert users on version 1.25 to migrate to version 1.26.

We advise any team currently using the deprecated Kubernetes volume types to plan their migration immediately. The affected drivers that need to be migrated to `*.csi.azure.com` are `kubernetes.io` and `azureFile`.

### AllowedFlexVolumes + FlexVolumeDriver

In Kubernetes, FlexVolume is a pluggable interface that allows third-party storage providers to create custom volume drivers for use in Kubernetes clusters. These drivers can be used to mount external storage systems or add functionality, such as encryption or compression, to Kubernetes volumes.

The FlexVolume interface is designed to be flexible and extensible, and can be used with a wide range of storage systems, including cloud storage services, network-attached storage (NAS) devices, and local storage devices.

FlexVolume drivers are installed on the nodes in a Kubernetes cluster and are invoked by kubelet when a Pod requests a volume backed by the driver. The FlexVolume driver then communicates with the external storage system to create or mount the volume and provides Kubernetes with the necessary information to mount the volume in the Pod.