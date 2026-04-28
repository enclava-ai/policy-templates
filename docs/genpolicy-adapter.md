# Genpolicy Adapter

The signing service now has a command adapter for Kata `genpolicy`, but local CI
does not execute upstream `genpolicy` because the binary and platform settings
are not present in this repo.

The adapter is intentionally explicit:

- `GENPOLICY_BIN` selects the binary path, default `genpolicy`.
- `GENPOLICY_VERSION_PIN` records the platform release pin, default
  `unconfigured-local`.
- `GENPOLICY_SETTINGS_DIR` optionally adds `-j <dir>`.
- Invocation shape is `genpolicy -y pod.yaml [-j <settings-dir>]`.

The generated `pod.yaml` is derived only from the verified signed
`DeploymentDescriptor`: app name, namespace, service account, runtime class,
image digest, command, args, env, ports, mounts, capabilities, resources, and
security context.

Unit coverage asserts the exact argv and manifest fields. A deployment that
sets the env vars can call the adapter's `run()` path, which writes the manifest
to a temporary directory and captures stdout as the generated agent policy. The
current `/sign` endpoint does not claim genpolicy execution unless that `run()`
path is wired into the release renderer.

Source contract checked while implementing: Kata documents `genpolicy -y
test.yaml` and optional settings via `-j` for settings directories:
https://github.com/kata-containers/kata-containers/blob/main/src/tools/genpolicy/README.md
