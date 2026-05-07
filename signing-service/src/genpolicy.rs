use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::descriptor::{DeploymentDescriptor, EnvVar, Resources};

const KATA_RUNTIME_HANDLER_ANNOTATION: &str = "io.containerd.cri.runtime-handler";
const KATA_KERNEL_PARAMS_ANNOTATION: &str = "io.katacontainers.config.hypervisor.kernel_params";
const KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
const KATA_RUNTIME_CC_INIT_DATA_ANNOTATION: &str = "io.katacontainers.config.runtime.cc_init_data";
const KATA_RUNTIME_HANDLER: &str = "kata-qemu-snp";
const KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";
const ATTESTATION_PROXY_IMAGE_REPO: &str = "ghcr.io/enclava-ai/attestation-proxy";
const CADDY_INGRESS_IMAGE_REPO: &str = "ghcr.io/enclava-ai/caddy-ingress";
const ENCLAVA_WAIT_EXEC_PATH: &str = "/enclava-tools/enclava-wait-exec";

#[derive(Debug, Clone)]
pub struct GenpolicyConfig {
    pub binary: PathBuf,
    pub version_pin: String,
    pub rules_path: PathBuf,
    pub settings_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenpolicyInvocation {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub manifest_yaml: String,
    pub version_pin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAgentPolicy {
    pub policy_text: String,
    pub invocation: GenpolicyInvocation,
}

impl GenpolicyConfig {
    pub fn from_env() -> Self {
        let binary = std::env::var("GENPOLICY_BIN").unwrap_or_else(|_| "genpolicy".to_string());
        let version_pin = std::env::var("GENPOLICY_VERSION_PIN")
            .unwrap_or_else(|_| "unconfigured-local".to_string());
        let rules_path =
            std::env::var("GENPOLICY_RULES_PATH").unwrap_or_else(|_| "rules.rego".to_string());
        let settings_dir = std::env::var("GENPOLICY_SETTINGS_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        Self {
            binary: PathBuf::from(binary),
            version_pin,
            rules_path: PathBuf::from(rules_path),
            settings_dir,
        }
    }

    pub fn require_pinned_version(&self) -> Result<()> {
        let pin = self.version_pin.trim();
        if pin.is_empty() || pin.contains("unconfigured") || pin.contains("unpinned") {
            bail!("GENPOLICY_VERSION_PIN must be a concrete pinned genpolicy release");
        }
        Ok(())
    }

    pub fn build_invocation(
        &self,
        descriptor: &DeploymentDescriptor,
    ) -> Result<GenpolicyInvocation> {
        let manifest_yaml = render_pod_manifest(descriptor)?;
        let mut args = vec![
            "-y".to_string(),
            "pod.yaml".to_string(),
            "-p".to_string(),
            self.rules_path.display().to_string(),
            "-r".to_string(),
        ];
        if let Some(settings_dir) = &self.settings_dir {
            args.push("-j".to_string());
            args.push(settings_dir.display().to_string());
        }
        Ok(GenpolicyInvocation {
            binary: self.binary.clone(),
            args,
            manifest_yaml,
            version_pin: self.version_pin.clone(),
        })
    }

    pub fn run(&self, descriptor: &DeploymentDescriptor) -> Result<GeneratedAgentPolicy> {
        let invocation = self.build_invocation(descriptor)?;
        let dir = tempfile::tempdir().context("creating genpolicy work dir")?;
        let manifest_path = dir.path().join("pod.yaml");
        std::fs::write(&manifest_path, &invocation.manifest_yaml)
            .with_context(|| format!("writing {}", manifest_path.display()))?;

        let mut args = vec![
            "-y".to_string(),
            manifest_path.display().to_string(),
            "-p".to_string(),
            self.rules_path.display().to_string(),
            "-r".to_string(),
        ];
        if let Some(settings_dir) = &self.settings_dir {
            args.push("-j".to_string());
            args.push(settings_dir.display().to_string());
        }

        let output = Command::new(&self.binary)
            .args(&args)
            .current_dir(dir.path())
            .output()
            .with_context(|| format!("executing genpolicy binary {}", self.binary.display()))?;
        if !output.status.success() {
            bail!(
                "genpolicy failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(GeneratedAgentPolicy {
            policy_text: String::from_utf8(output.stdout)
                .context("genpolicy output is not UTF-8")?,
            invocation,
        })
    }
}

fn render_pod_manifest(descriptor: &DeploymentDescriptor) -> Result<String> {
    let pod_name = format!("{}-0", descriptor.app_name);
    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": descriptor.namespace,
            "annotations": cap_runtime_annotations(),
        },
        "spec": {
            "runtimeClassName": descriptor.expected_runtime_class,
            "securityContext": {
                "fsGroup": 10001,
                "fsGroupChangePolicy": "OnRootMismatch",
                "supplementalGroups": [6],
            },
            "initContainers": [
                attestation_proxy_container(descriptor),
                enclava_tools_container()?,
            ],
            "containers": [
                app_container(descriptor),
                tenant_ingress_container(descriptor),
                enclava_init_container()?,
            ],
            "volumes": cap_volumes(descriptor),
        },
    });
    serde_yaml::to_string(&pod).context("rendering genpolicy pod manifest")
}

fn cap_runtime_annotations() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            KATA_RUNTIME_HANDLER_ANNOTATION,
            KATA_RUNTIME_HANDLER.to_string(),
        ),
        (
            KATA_KERNEL_PARAMS_ANNOTATION,
            format!("agent.aa_kbc_params=cc_kbc::{KBS_URL} agent.guest_components_rest_api=all"),
        ),
        (
            KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION,
            "enclava-dynamic-cc-init-data".to_string(),
        ),
        (
            KATA_RUNTIME_CC_INIT_DATA_ANNOTATION,
            "enclava-dynamic-cc-init-data".to_string(),
        ),
    ])
}

fn image_ref(repo: &str, digest: &str) -> String {
    format!("{repo}@{digest}")
}

fn enclava_init_image() -> Result<String> {
    let image = match std::env::var("ENCLAVA_INIT_IMAGE") {
        Ok(image) => image,
        Err(_err) if cfg!(test) => {
            "ghcr.io/enclava-ai/enclava-init@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
        }
        Err(err) => return Err(err).context("ENCLAVA_INIT_IMAGE must be set for CAP genpolicy sidecars"),
    };
    if !image.contains("@sha256:") {
        bail!("ENCLAVA_INIT_IMAGE must be digest-pinned with @sha256:");
    }
    Ok(image)
}

fn value_env(name: &str, value: impl Into<String>) -> Value {
    json!({"name": name, "value": value.into()})
}

fn field_env(name: &str, field_path: &str) -> Value {
    json!({
        "name": name,
        "valueFrom": {
            "fieldRef": {
                "fieldPath": field_path,
            },
        },
    })
}

fn kubernetes_service_host() -> String {
    std::env::var("GENPOLICY_KUBERNETES_SERVICE_HOST").unwrap_or_else(|_| "10.43.0.1".to_string())
}

fn kubernetes_service_env() -> Vec<Value> {
    let host = kubernetes_service_host();
    vec![
        value_env("KUBERNETES_SERVICE_PORT", "443"),
        value_env("KUBERNETES_SERVICE_PORT_HTTPS", "443"),
        value_env("KUBERNETES_PORT", format!("tcp://{host}:443")),
        value_env("KUBERNETES_PORT_443_TCP", format!("tcp://{host}:443")),
        value_env("KUBERNETES_PORT_443_TCP_PROTO", "tcp"),
        value_env("KUBERNETES_PORT_443_TCP_PORT", "443"),
        value_env("KUBERNETES_PORT_443_TCP_ADDR", host.clone()),
        value_env("KUBERNETES_SERVICE_HOST", host),
    ]
}

fn with_kubernetes_service_env(mut env: Vec<Value>) -> Vec<Value> {
    env.extend(kubernetes_service_env());
    env
}

fn mount(name: &str, mount_path: &str, read_only: bool) -> Value {
    json!({
        "name": name,
        "mountPath": mount_path,
        "readOnly": read_only,
    })
}

fn mount_with_propagation(name: &str, mount_path: &str, propagation: &str) -> Value {
    json!({
        "name": name,
        "mountPath": mount_path,
        "mountPropagation": propagation,
    })
}

fn mount_with_subpath(name: &str, mount_path: &str, sub_path: &str, propagation: &str) -> Value {
    json!({
        "name": name,
        "mountPath": mount_path,
        "subPath": sub_path,
        "mountPropagation": propagation,
    })
}

fn storage_subdir(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "-")
}

fn caps(drop: &[&str], add: &[&str]) -> Value {
    let mut capabilities = Map::new();
    capabilities.insert(
        "drop".to_string(),
        Value::Array(drop.iter().map(|value| json!(value)).collect()),
    );
    if !add.is_empty() {
        capabilities.insert(
            "add".to_string(),
            Value::Array(add.iter().map(|value| json!(value)).collect()),
        );
    }
    Value::Object(capabilities)
}

fn security_context(
    run_as_user: u32,
    run_as_group: u32,
    read_only_root_fs: bool,
    allow_privilege_escalation: bool,
    privileged: bool,
    capabilities: Value,
) -> Value {
    json!({
        "runAsUser": run_as_user,
        "runAsGroup": run_as_group,
        "readOnlyRootFilesystem": read_only_root_fs,
        "allowPrivilegeEscalation": allow_privilege_escalation,
        "privileged": privileged,
        "capabilities": capabilities,
    })
}

fn resources(
    request_cpu: &str,
    request_memory: &str,
    limit_cpu: &str,
    limit_memory: &str,
) -> Value {
    json!({
        "requests": {
            "cpu": request_cpu,
            "memory": request_memory,
        },
        "limits": {
            "cpu": limit_cpu,
            "memory": limit_memory,
        },
    })
}

fn app_container(descriptor: &DeploymentDescriptor) -> Value {
    let oci = &descriptor.oci_runtime_spec;
    let mut volume_mounts = vec![
        mount("startup", "/startup", true),
        mount("enclava-tools", "/enclava-tools", true),
        mount("unlock-socket", "/run/enclava", false),
        mount_with_propagation("state-mount", "/state", "HostToContainer"),
    ];
    for storage_path in oci
        .mounts
        .iter()
        .filter(|mount| mount.source == "state-mount")
        .map(|mount| mount.destination.as_str())
        .filter(|path| *path != "/state")
    {
        volume_mounts.push(mount_with_subpath(
            "state-mount",
            storage_path,
            &storage_subdir(storage_path),
            "HostToContainer",
        ));
    }

    let env = with_kubernetes_service_env(
        oci.env
            .iter()
            .map(|env| value_env(&env.name, &env.value))
            .collect(),
    );

    json!({
        "name": "web",
        "image": descriptor.image_ref,
        "command": [ENCLAVA_WAIT_EXEC_PATH],
        "args": oci.args,
        "env": env,
        "ports": oci.ports.iter().map(|port| json!({
            "containerPort": port.container_port,
            "protocol": port.protocol,
        })).collect::<Vec<_>>(),
        "volumeMounts": volume_mounts,
        "securityContext": security_context(10001, 10001, true, false, false, caps(&["ALL"], &[])),
        "resources": ResourcesYaml::from(&oci.resources),
    })
}

fn attestation_proxy_container(descriptor: &DeploymentDescriptor) -> Value {
    json!({
        "name": "attestation-proxy",
        "image": image_ref(ATTESTATION_PROXY_IMAGE_REPO, &descriptor.sidecars.attestation_proxy_digest),
        "restartPolicy": "Always",
        "command": ["/attestation-proxy"],
        "ports": [
            {"containerPort": 8081, "name": "attest-http"},
            {"containerPort": 8443, "name": "attestation"},
        ],
        "env": with_kubernetes_service_env(vec![
            value_env("ATTESTATION_WORKLOAD_CONTAINER", "web"),
            field_env("ATTESTATION_POD_NAME", "metadata.name"),
            field_env("ATTESTATION_POD_NAMESPACE", "metadata.namespace"),
            value_env("ATTESTATION_PROFILE", "coco-sev-snp"),
            value_env("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
            value_env("ATTESTATION_WORKLOAD_IMAGE", descriptor.image_ref.clone()),
            value_env("ATTESTATION_TLS_PORT", "8443"),
            value_env("TEE_DOMAIN", descriptor.tee_domain.clone()),
            value_env("STORAGE_OWNERSHIP_MODE", "auto-unlock"),
            value_env("INSTANCE_ID", format!("{}-{}", descriptor.namespace, descriptor.app_name)),
            value_env("OWNER_CIPHERTEXT_BACKEND", "kbs-resource"),
            value_env("OWNER_SEED_HANDOFF_SLOTS", "app-data"),
            value_env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
            value_env("KBS_RESOURCE_CACHE_SECONDS", "300"),
            value_env("KBS_RESOURCE_FAILURE_CACHE_SECONDS", "30"),
            value_env("KBS_FETCH_RETRIES", "120"),
            value_env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
            value_env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
            value_env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
        ]),
        "volumeMounts": [
            mount("ownership-signal", "/run/ownership-signal", false),
            mount("unlock-socket", "/run/enclava", false),
        ],
        "securityContext": security_context(65532, 65532, true, false, false, caps(&["ALL"], &[])),
        "resources": resources("100m", "128Mi", "500m", "256Mi"),
    })
}

fn enclava_tools_container() -> Result<Value> {
    Ok(json!({
        "name": "enclava-tools",
        "image": enclava_init_image()?,
        "command": ["/bin/sh", "-ec"],
        "args": ["cp /usr/local/bin/enclava-wait-exec /enclava-tools/enclava-wait-exec && chmod 0555 /enclava-tools/enclava-wait-exec"],
        "env": kubernetes_service_env(),
        "volumeMounts": [
            mount("enclava-tools", "/enclava-tools", false),
        ],
        "securityContext": security_context(0, 0, true, false, false, caps(&["ALL"], &[])),
        "resources": resources("10m", "16Mi", "50m", "32Mi"),
    }))
}

fn tenant_ingress_container(descriptor: &DeploymentDescriptor) -> Value {
    json!({
        "name": "tenant-ingress",
        "image": image_ref(CADDY_INGRESS_IMAGE_REPO, &descriptor.sidecars.caddy_digest),
        "command": [ENCLAVA_WAIT_EXEC_PATH],
        "args": ["caddy", "run", "--config", "/etc/caddy/Caddyfile"],
        "ports": [
            {"containerPort": 443, "name": "https"},
        ],
        "env": with_kubernetes_service_env(vec![
            field_env("POD_NAME", "metadata.name"),
            field_env("POD_NAMESPACE", "metadata.namespace"),
            value_env("CADDY_SEED_PATH", "/state/caddy/seed"),
            value_env("VOLUME_MOUNT_POINT", "/state/tls-state"),
            value_env("XDG_DATA_HOME", "/state/tls-state/caddy"),
            value_env("ENCLAVA_CONTAINER_NAME", "tenant-ingress"),
            value_env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"),
            value_env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
        ]),
        "volumeMounts": [
            mount("tenant-ingress-caddyfile", "/etc/caddy", true),
            mount("enclava-tools", "/enclava-tools", true),
            mount("unlock-socket", "/run/enclava", false),
            mount_with_propagation("state-mount", "/state", "HostToContainer"),
            mount_with_propagation("tls-state-mount", "/state/tls-state", "HostToContainer"),
        ],
        "securityContext": security_context(10002, 10002, true, false, false, caps(&["ALL"], &["NET_BIND_SERVICE"])),
        "resources": resources("100m", "128Mi", "500m", "256Mi"),
    })
}

fn enclava_init_container() -> Result<Value> {
    Ok(json!({
        "name": "enclava-init",
        "image": enclava_init_image()?,
        "command": ["/usr/local/bin/enclava-init"],
        "env": with_kubernetes_service_env(vec![
            value_env("ENCLAVA_INIT_CONFIG", "/etc/enclava-init/config.toml"),
            value_env("ENCLAVA_INIT_STAY_ALIVE", "true"),
            value_env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
            value_env("ENCLAVA_INIT_STARTED_DIR", "/run/enclava/containers"),
            value_env("ENCLAVA_INIT_WAIT_FOR_CONTAINERS", "web,tenant-ingress"),
        ]),
        "volumeMounts": [
            mount_with_propagation("state-mount", "/state", "Bidirectional"),
            mount_with_propagation("tls-state-mount", "/state/tls-state", "Bidirectional"),
            mount("unlock-socket", "/run/enclava", false),
            mount("enclava-init-config", "/etc/enclava-init", true),
        ],
        "volumeDevices": [
            {"name": "state", "devicePath": "/dev/csi0"},
            {"name": "tls-state", "devicePath": "/dev/csi1"},
        ],
        "securityContext": security_context(0, 0, true, true, true, caps(&["ALL"], &["SYS_ADMIN"])),
        "resources": resources("50m", "64Mi", "250m", "128Mi"),
    }))
}

fn cap_volumes(descriptor: &DeploymentDescriptor) -> Vec<Value> {
    vec![
        json!({"name": "logs", "emptyDir": {}}),
        json!({"name": "ownership-signal", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        config_map_volume(
            "tenant-ingress-caddyfile",
            format!("{}-tenant-ingress", descriptor.app_name),
        ),
        config_map_volume("startup", format!("{}-startup", descriptor.app_name)),
        json!({"name": "unlock-socket", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        json!({"name": "enclava-tools", "emptyDir": {}}),
        json!({"name": "state-mount", "emptyDir": {}}),
        json!({"name": "tls-state-mount", "emptyDir": {}}),
        config_map_volume(
            "enclava-init-config",
            format!("{}-enclava-init", descriptor.app_name),
        ),
    ]
}

fn config_map_volume(name: &str, config_map_name: String) -> Value {
    json!({
        "name": name,
        "configMap": {
            "name": config_map_name,
        },
    })
}

#[derive(Serialize)]
struct ResourcesYaml<'a> {
    requests: ResourceMap<'a>,
    limits: ResourceMap<'a>,
}

impl<'a> From<&'a Resources> for ResourcesYaml<'a> {
    fn from(value: &'a Resources) -> Self {
        Self {
            requests: ResourceMap(&value.requests),
            limits: ResourceMap(&value.limits),
        }
    }
}

struct ResourceMap<'a>(&'a [EnvVar]);

impl Serialize for ResourceMap<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut sorted: Vec<&EnvVar> = self.0.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut map = serializer.serialize_map(Some(sorted.len()))?;
        for entry in sorted {
            map.serialize_entry(&entry.name, &entry.value)?;
        }
        map.end()
    }
}

#[allow(dead_code)]
fn _assert_manifest_path(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::tests::fixed_descriptor;

    #[test]
    fn invocation_pins_binary_settings_and_manifest_input() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("/opt/kata/bin/genpolicy"),
            version_pin: "kata-containers-3.12.0".to_string(),
            rules_path: PathBuf::from("/etc/enclava/genpolicy/rules.rego"),
            settings_dir: Some(PathBuf::from("/etc/enclava/genpolicy")),
        };
        let invocation = config.build_invocation(&fixed_descriptor()).unwrap();

        assert_eq!(invocation.binary, PathBuf::from("/opt/kata/bin/genpolicy"));
        assert_eq!(
            invocation.args,
            vec![
                "-y".to_string(),
                "pod.yaml".to_string(),
                "-p".to_string(),
                "/etc/enclava/genpolicy/rules.rego".to_string(),
                "-r".to_string(),
                "-j".to_string(),
                "/etc/enclava/genpolicy".to_string()
            ]
        );
        assert_eq!(invocation.version_pin, "kata-containers-3.12.0");
        assert!(invocation
            .manifest_yaml
            .contains("runtimeClassName: kata-qemu-snp"));
        assert!(invocation.manifest_yaml.contains("name: demo-0"));
        assert!(invocation
            .manifest_yaml
            .contains("io.containerd.cri.runtime-handler: kata-qemu-snp"));
        assert!(invocation.manifest_yaml.contains(
            "io.katacontainers.config.hypervisor.kernel_params: agent.aa_kbc_params=cc_kbc::http://kbs-service.trustee-operator-system.svc.cluster.local:8080 agent.guest_components_rest_api=all"
        ));
        assert!(invocation.manifest_yaml.contains(
            "io.katacontainers.config.hypervisor.cc_init_data: enclava-dynamic-cc-init-data"
        ));
        assert!(invocation.manifest_yaml.contains(
            "io.katacontainers.config.runtime.cc_init_data: enclava-dynamic-cc-init-data"
        ));
        assert!(!invocation.manifest_yaml.contains("serviceAccountName:"));
        assert!(!invocation
            .manifest_yaml
            .contains("automountServiceAccountToken"));
        assert!(!invocation.manifest_yaml.contains("enableServiceLinks"));
        assert!(invocation.manifest_yaml.contains("fsGroup: 10001"));
        assert!(invocation.manifest_yaml.contains("supplementalGroups:"));
        assert!(!invocation.manifest_yaml.contains("defaultMode"));
        assert!(invocation
            .manifest_yaml
            .contains("name: KUBERNETES_SERVICE_HOST"));
        assert!(invocation.manifest_yaml.contains("value: 10.43.0.1"));
        assert!(invocation
            .manifest_yaml
            .contains("image: ghcr.io/enclava-ai/demo@sha256:aaaa"));
        assert!(invocation.manifest_yaml.contains("- name: A"));
        assert!(invocation.manifest_yaml.contains("value: '1'"));
    }

    #[test]
    fn rejects_unpinned_version_label() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("genpolicy"),
            version_pin: "kata-containers/genpolicy-unpinned-dev".to_string(),
            rules_path: PathBuf::from("rules.rego"),
            settings_dir: None,
        };
        assert!(config.require_pinned_version().is_err());
    }
}
