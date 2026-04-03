//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

//! Utilities for E2E testing

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

/// Default namespace for E2E tests
pub const E2E_NAMESPACE: &str = "vault-e2e-test";

/// Default Kind cluster name
pub const KIND_CLUSTER_NAME: &str = "vault-e2e";

/// Vault service URL within the cluster
pub const VAULT_SERVICE_URL: &str = "http://vault:8200";

/// Check if Kind cluster exists
pub fn kind_cluster_exists(cluster_name: &str) -> Result<bool> {
    let output = Command::new("kind")
        .args(["get", "clusters"])
        .output()
        .context("Failed to execute 'kind get clusters'. Is Kind installed?")?;

    if !output.status.success() {
        bail!("Failed to list Kind clusters");
    }

    let clusters = String::from_utf8_lossy(&output.stdout);
    Ok(clusters.lines().any(|line| line.trim() == cluster_name))
}

/// Check if kubectl is available and configured for the Kind cluster
pub fn kubectl_configured() -> Result<bool> {
    let output = Command::new("kubectl")
        .args(["cluster-info"])
        .output()
        .context("Failed to execute kubectl. Is kubectl installed?")?;

    Ok(output.status.success())
}

/// Check if namespace exists
pub fn namespace_exists(namespace: &str) -> Result<bool> {
    let output = Command::new("kubectl")
        .args(["get", "namespace", namespace])
        .output()
        .context("Failed to check namespace")?;

    Ok(output.status.success())
}

/// Wait for pod to be ready
pub async fn wait_for_pod_ready(namespace: &str, pod_label: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=condition=Ready",
            "pod",
            "-l",
            pod_label,
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Pod with label {} did not become ready: {}", pod_label, stderr);
    }

    Ok(())
}

/// Wait for deployment to be ready
pub async fn wait_for_deployment_ready(namespace: &str, deployment_name: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=condition=Available",
            &format!("deployment/{}", deployment_name),
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for deployment")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Deployment {} did not become ready: {}", deployment_name, stderr);
    }

    Ok(())
}

/// Execute command in pod
pub fn kubectl_exec(namespace: &str, pod_name: &str, container: &str, command: &[&str]) -> Result<String> {
    let mut args = vec!["exec", "-n", namespace, pod_name, "-c", container, "--"];
    args.extend_from_slice(command);

    let output = Command::new("kubectl")
        .args(&args)
        .output()
        .context("Failed to execute command in pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Command failed: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get pod logs
pub fn get_pod_logs(namespace: &str, pod_name: &str, container: &str) -> Result<String> {
    let output = Command::new("kubectl")
        .args(["logs", "-n", namespace, pod_name, "-c", container])
        .output()
        .context("Failed to get pod logs")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Delete pod
pub fn delete_pod(namespace: &str, pod_name: &str) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "delete",
            "pod",
            "-n",
            namespace,
            pod_name,
            "--grace-period=0",
            "--force",
        ])
        .output()
        .context("Failed to delete pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to delete pod: {}", stderr);
    }

    Ok(())
}

/// Wait for pod to be deleted
pub async fn wait_for_pod_deleted(namespace: &str, pod_name: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=delete",
            &format!("pod/{}", pod_name),
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for pod deletion")?;

    // kubectl wait --for=delete returns success when resource is deleted
    // It returns error if timeout occurs
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Pod {} was not deleted within timeout: {}", pod_name, stderr);
    }

    Ok(())
}

/// Wait for all pods with a label selector to be deleted
pub async fn wait_for_pods_deleted_by_label(namespace: &str, label_selector: &str, timeout_secs: u64) -> Result<()> {
    // First check if there are any pods with this label
    let check_output = Command::new("kubectl")
        .args(["get", "pods", "-n", namespace, "-l", label_selector, "-o", "name"])
        .output()
        .context("Failed to check for pods")?;

    // If no pods exist, we're done (trim whitespace — kubectl may emit a trailing newline)
    if check_output.stdout.trim_ascii().is_empty() {
        return Ok(());
    }

    // Wait for all pods with this label to be deleted
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=delete",
            "pod",
            "-l",
            label_selector,
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for pods deletion")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Pods with label {} were not deleted within timeout: {}",
            label_selector,
            stderr
        );
    }

    Ok(())
}

/// Wait for a file to exist inside a pod container
pub async fn wait_for_file_in_pod(
    namespace: &str,
    pod_name: &str,
    container: &str,
    file_path: &str,
    timeout_secs: u64,
) -> Result<()> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            bail!(
                "Timeout waiting for file {} to exist in pod {}/{}",
                file_path,
                pod_name,
                container
            );
        }

        // Try to check if file exists
        let output = Command::new("kubectl")
            .args([
                "exec", "-n", namespace, pod_name, "-c", container, "--", "test", "-f", file_path,
            ])
            .output()
            .context("Failed to check if file exists")?;

        // If test -f succeeds, file exists
        if output.status.success() {
            return Ok(());
        }

        sleep(Duration::from_millis(500)).await;
    }
}

/// Apply Kubernetes manifest
pub fn kubectl_apply(manifest_path: &str) -> Result<()> {
    let output = Command::new("kubectl")
        .args(["apply", "-f", manifest_path])
        .output()
        .context("Failed to apply manifest")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to apply manifest: {}", stderr);
    }

    Ok(())
}

/// Delete Kubernetes resources
pub fn kubectl_delete(manifest_path: &str) -> Result<()> {
    let output = Command::new("kubectl")
        .args(["delete", "-f", manifest_path, "--ignore-not-found"])
        .output()
        .context("Failed to delete resources")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to delete resources: {}", stderr);
    }

    Ok(())
}

/// Apply Kubernetes manifest from a string (using stdin)
pub fn kubectl_apply_stdin(manifest_content: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn kubectl apply")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(manifest_content.as_bytes())
            .context("Failed to write manifest to kubectl stdin")?;
    }

    let output = child.wait_with_output().context("Failed to wait for kubectl apply")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to apply manifest from stdin: {}", stderr);
    }

    Ok(())
}

/// Delete a pod by name
pub fn kubectl_delete_pod(namespace: &str, pod_name: &str) -> Result<()> {
    let output = Command::new("kubectl")
        .args(["delete", "pod", pod_name, "-n", namespace, "--ignore-not-found"])
        .output()
        .context("Failed to delete pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to delete pod {}: {}", pod_name, stderr);
    }

    Ok(())
}

/// Get Vault root token from secret
pub fn get_vault_root_token(namespace: &str) -> Result<String> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "secret",
            "vault-root-token",
            "-n",
            namespace,
            "-o",
            "jsonpath={.data.token}",
        ])
        .output()
        .context("Failed to get Vault root token")?;

    if !output.status.success() {
        bail!("Failed to retrieve Vault root token from secret");
    }

    let token_b64 = String::from_utf8_lossy(&output.stdout);
    let token_bytes = STANDARD
        .decode(token_b64.trim())
        .context("Failed to decode base64 token")?;

    Ok(String::from_utf8(token_bytes)
        .context("Failed to parse token as UTF-8")?
        .trim()
        .to_string())
}

/// Port forward to a service (returns child process that must be kept alive)
pub fn port_forward(namespace: &str, service: &str, local_port: u16, remote_port: u16) -> Result<std::process::Child> {
    let child = Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            namespace,
            &format!("svc/{}", service),
            &format!("{}:{}", local_port, remote_port),
        ])
        .spawn()
        .context("Failed to start port-forward")?;

    Ok(child)
}

/// Copy a file from host to pod
/// Wait for a container to complete and return its exit code
/// Returns Ok(exit_code) if container terminated, or error if timeout
pub async fn wait_for_container_completion(
    namespace: &str,
    pod_name: &str,
    container: &str,
    timeout_secs: u64,
) -> Result<i32> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            bail!(
                "Timeout waiting for container {} in pod {} to complete",
                container,
                pod_name
            );
        }

        // Get container status
        let output = Command::new("kubectl")
            .args([
                "get",
                "pod",
                "-n",
                namespace,
                pod_name,
                "-o",
                &format!(
                    "jsonpath={{.status.containerStatuses[?(@.name==\"{}\")].state}}",
                    container
                ),
            ])
            .output()
            .context("Failed to get container status")?;

        let status = String::from_utf8_lossy(&output.stdout);

        // Check if container has terminated
        if status.contains("\"terminated\"") {
            // Get exit code
            let exit_code_output = Command::new("kubectl")
                .args([
                    "get",
                    "pod",
                    "-n",
                    namespace,
                    pod_name,
                    "-o",
                    &format!(
                        "jsonpath={{.status.containerStatuses[?(@.name==\"{}\")].state.terminated.exitCode}}",
                        container
                    ),
                ])
                .output()
                .context("Failed to get container exit code")?;

            let exit_code_str = String::from_utf8_lossy(&exit_code_output.stdout);
            let exit_code = exit_code_str
                .trim()
                .parse::<i32>()
                .context("Failed to parse exit code")?;

            return Ok(exit_code);
        }

        sleep(Duration::from_millis(500)).await;
    }
}
