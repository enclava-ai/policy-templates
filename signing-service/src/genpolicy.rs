use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::descriptor::{DeploymentDescriptor, EnvVar, Mount, OciRuntimeSpec, Port, Resources};

const KATA_RUNTIME_HANDLER_ANNOTATION: &str = "io.containerd.cri.runtime-handler";
const KATA_KERNEL_PARAMS_ANNOTATION: &str = "io.katacontainers.config.hypervisor.kernel_params";
const KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
const KATA_RUNTIME_CC_INIT_DATA_ANNOTATION: &str = "io.katacontainers.config.runtime.cc_init_data";
const KATA_RUNTIME_HANDLER: &str = "kata-qemu-snp";
const KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";

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
    let pod = PodManifest {
        api_version: "v1",
        kind: "Pod",
        metadata: Metadata {
            name: &descriptor.app_name,
            namespace: &descriptor.namespace,
            annotations: cap_runtime_annotations(),
        },
        spec: PodSpec {
            runtime_class_name: &descriptor.expected_runtime_class,
            service_account_name: &descriptor.service_account,
            containers: vec![container_from_descriptor(descriptor)],
            volumes: volumes_from_mounts(&descriptor.oci_runtime_spec.mounts),
        },
    };
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

fn container_from_descriptor(descriptor: &DeploymentDescriptor) -> Container<'_> {
    let oci = &descriptor.oci_runtime_spec;
    Container {
        name: &descriptor.app_name,
        image: &descriptor.image_ref,
        command: &oci.command,
        args: &oci.args,
        env: oci.env.iter().map(Env::from).collect(),
        ports: oci.ports.iter().map(ContainerPort::from).collect(),
        volume_mounts: oci
            .mounts
            .iter()
            .enumerate()
            .map(VolumeMount::from)
            .collect(),
        security_context: SecurityContextYaml::from(oci),
        resources: ResourcesYaml::from(&oci.resources),
    }
}

fn volumes_from_mounts(mounts: &[Mount]) -> Vec<Volume<'_>> {
    mounts
        .iter()
        .enumerate()
        .map(|(idx, mount)| Volume {
            name: format!("mount-{idx}"),
            host_path: HostPath {
                path: mount.source.as_str(),
                kind: mount.mount_type.as_str(),
            },
        })
        .collect()
}

#[derive(Serialize)]
struct PodManifest<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    metadata: Metadata<'a>,
    spec: PodSpec<'a>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    name: &'a str,
    namespace: &'a str,
    annotations: BTreeMap<&'a str, String>,
}

#[derive(Serialize)]
struct PodSpec<'a> {
    #[serde(rename = "runtimeClassName")]
    runtime_class_name: &'a str,
    #[serde(rename = "serviceAccountName")]
    service_account_name: &'a str,
    containers: Vec<Container<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<Volume<'a>>,
}

#[derive(Serialize)]
struct Container<'a> {
    name: &'a str,
    image: &'a str,
    command: &'a [String],
    args: &'a [String],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    env: Vec<Env<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<ContainerPort<'a>>,
    #[serde(rename = "volumeMounts", skip_serializing_if = "Vec::is_empty")]
    volume_mounts: Vec<VolumeMount<'a>>,
    #[serde(rename = "securityContext")]
    security_context: SecurityContextYaml<'a>,
    resources: ResourcesYaml<'a>,
}

#[derive(Serialize)]
struct Env<'a> {
    name: &'a str,
    value: &'a str,
}

impl<'a> From<&'a EnvVar> for Env<'a> {
    fn from(value: &'a EnvVar) -> Self {
        Self {
            name: &value.name,
            value: &value.value,
        }
    }
}

#[derive(Serialize)]
struct ContainerPort<'a> {
    #[serde(rename = "containerPort")]
    container_port: u32,
    protocol: &'a str,
}

impl<'a> From<&'a Port> for ContainerPort<'a> {
    fn from(value: &'a Port) -> Self {
        Self {
            container_port: value.container_port,
            protocol: &value.protocol,
        }
    }
}

#[derive(Serialize)]
struct VolumeMount<'a> {
    name: String,
    #[serde(rename = "mountPath")]
    mount_path: &'a str,
    #[serde(rename = "readOnly")]
    read_only: bool,
}

impl<'a> From<(usize, &'a Mount)> for VolumeMount<'a> {
    fn from((idx, value): (usize, &'a Mount)) -> Self {
        Self {
            name: format!("mount-{idx}"),
            mount_path: &value.destination,
            read_only: value.options.iter().any(|option| option == "ro"),
        }
    }
}

#[derive(Serialize)]
struct Volume<'a> {
    name: String,
    #[serde(rename = "hostPath")]
    host_path: HostPath<'a>,
}

#[derive(Serialize)]
struct HostPath<'a> {
    path: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Serialize)]
struct SecurityContextYaml<'a> {
    #[serde(rename = "runAsUser")]
    run_as_user: u32,
    #[serde(rename = "runAsGroup")]
    run_as_group: u32,
    #[serde(rename = "readOnlyRootFilesystem")]
    read_only_root_fs: bool,
    #[serde(rename = "allowPrivilegeEscalation")]
    allow_privilege_escalation: bool,
    privileged: bool,
    capabilities: CapabilitiesYaml<'a>,
}

impl<'a> From<&'a OciRuntimeSpec> for SecurityContextYaml<'a> {
    fn from(value: &'a OciRuntimeSpec) -> Self {
        Self {
            run_as_user: value.security_context.run_as_user,
            run_as_group: value.security_context.run_as_group,
            read_only_root_fs: value.security_context.read_only_root_fs,
            allow_privilege_escalation: value.security_context.allow_privilege_escalation,
            privileged: value.security_context.privileged,
            capabilities: CapabilitiesYaml {
                add: &value.capabilities.add,
                drop: &value.capabilities.drop,
            },
        }
    }
}

#[derive(Serialize)]
struct CapabilitiesYaml<'a> {
    add: &'a [String],
    drop: &'a [String],
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
        assert!(invocation
            .manifest_yaml
            .contains("serviceAccountName: cap-demo-sa"));
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
