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

//! E2E tests for Kubernetes + Vault sidecar pattern
//!
//! These tests deploy actual pods in a Kind cluster with Vault Agent sidecars
//! and verify that the HashicorpVaultClient with FileBasedVaultAuthClient
//! correctly reads tokens and performs Vault operations.

use crate::utils::*;
use anyhow::{Context, Result};

/// Generates a unique pod manifest with a given pod name
/// This allows multiple tests to run in parallel without conflicts
fn generate_test_pod_manifest(pod_name: &str) -> String {
    format!(
        r#"---
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: vault-e2e-test
  labels:
    app: {pod_name}
spec:
  serviceAccountName: test-app-sa

  # Init container to wait for Vault to be ready
  initContainers:
  - name: wait-for-vault
    image: busybox:1.36
    command:
    - 'sh'
    - '-c'
    - |
      echo "Waiting for Vault to be ready..."
      until wget -q -O- http://vault:8200/v1/sys/health > /dev/null 2>&1; do
        echo "Vault not ready yet, waiting..."
        sleep 2
      done
      echo "Vault is ready!"

  containers:
  # Vault Agent sidecar
  - name: vault-agent
    image: hashicorp/vault:1.15.0
    args:
    - "agent"
    - "-config=/vault/configs/vault-agent-config.hcl"
    - "-log-level=debug"
    env:
    - name: VAULT_ADDR
      value: "http://vault:8200"
    volumeMounts:
    - name: vault-token
      mountPath: /vault/secrets
    - name: vault-config
      mountPath: /vault/configs
    resources:
      requests:
        memory: "256Mi"
        cpu: "50m"
      limits:
        memory: "512Mi"
        cpu: "200m"

  # Test runner container - runs the vault-test binary
  - name: test-runner
    image: vault-test:local
    imagePullPolicy: Never
    command:
    - 'sh'
    - '-c'
    - |
      echo "Test runner started. Token file location: /vault/secrets/.vault-token"
      echo "Waiting for token file to be created by vault-agent..."

      # Wait for token file
      while [ ! -f /vault/secrets/.vault-token ]; do
        echo "Token file not found yet, waiting..."
        sleep 1
      done

      echo "Token file found!"
      echo "Starting vault-test binary..."

      # Run the test binary
      /usr/local/bin/vault-test
    env:
    - name: TEST_MODE
      value: "crud"
    - name: VAULT_URL
      value: "http://vault:8200"
    - name: TOKEN_FILE_PATH
      value: "/vault/secrets/.vault-token"
    volumeMounts:
    - name: vault-token
      mountPath: /vault/secrets
      readOnly: true
    resources:
      requests:
        memory: "64Mi"
        cpu: "50m"
      limits:
        memory: "128Mi"
        cpu: "100m"

  volumes:
  - name: vault-token
    emptyDir:
      medium: Memory
  - name: vault-config
    configMap:
      name: vault-agent-config

  restartPolicy: Never
"#,
        pod_name = pod_name
    )
}

/// Setup function to verify E2E environment is ready
async fn verify_e2e_setup() -> Result<()> {
    // Check Kind cluster exists
    if !kind_cluster_exists(KIND_CLUSTER_NAME)? {
        anyhow::bail!(
            "Kind cluster '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            KIND_CLUSTER_NAME
        );
    }

    // Check kubectl is configured
    if !kubectl_configured()? {
        anyhow::bail!("kubectl not configured or cluster not accessible");
    }

    // Check namespace exists
    if !namespace_exists(E2E_NAMESPACE)? {
        anyhow::bail!(
            "Namespace '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            E2E_NAMESPACE
        );
    }

    // Check Vault deployment is ready
    wait_for_deployment_ready(E2E_NAMESPACE, "vault", 60)
        .await
        .context("Vault deployment not ready")?;

    Ok(())
}

/// Test that HashicorpVaultClient with FileBasedVaultAuthClient works in K8s
///
/// This test:
/// 1. Deploys a pod with Vault Agent sidecar and test container
/// 2. Waits for the sidecar to authenticate and write the token file
/// 3. Test container automatically runs vault-test binary (from Docker image)
/// 4. Waits for the test container to complete
/// 5. Retrieves logs and verifies CRUD operations succeeded
///
/// Note: This test uses a unique pod name based on the process ID to allow
/// multiple test runs to execute in parallel without conflicts.
#[tokio::test]
#[ignore]
async fn test_hashicorp_vault_client_with_rust_binary() -> Result<()> {
    verify_e2e_setup().await?;

    // Generate unique pod name based on process ID to support parallel test execution
    let pid = std::process::id();
    let pod_name = format!("test-app-{}", pid);
    let pod_label = format!("app={}", pod_name);

    println!("Using unique pod name: {}", pod_name);

    // Clean up any leftover pods from previous runs (only from dead processes)
    let _ = kubectl_delete_pod(E2E_NAMESPACE, &pod_name);
    let _ = wait_for_pod_deleted(E2E_NAMESPACE, &pod_name, 30).await;

    // Generate and deploy test pod manifest with unique name
    println!("Deploying test pod with vault-test container...");
    let manifest = generate_test_pod_manifest(&pod_name);
    kubectl_apply_stdin(&manifest)?;

    // Wait for vault-agent to be ready (not the test-runner, since it will complete and exit)
    println!("Waiting for vault-agent to be ready...");
    wait_for_pod_ready(E2E_NAMESPACE, &pod_label, 120).await?;

    // Wait for the test-runner container to complete
    println!("Waiting for test-runner container to complete...");
    let exit_code = wait_for_container_completion(E2E_NAMESPACE, &pod_name, "test-runner", 120)
        .await
        .context("Failed to wait for container completion")?;

    // Get the logs from the test-runner container
    println!("Retrieving logs from test-runner container...");
    let logs = get_pod_logs(E2E_NAMESPACE, &pod_name, "test-runner")?;

    println!("Container logs:\n{}", logs);
    println!("Container exit code: {}", exit_code);

    // Verify the test succeeded
    assert_eq!(
        exit_code, 0,
        "Test container should exit with code 0, got {}",
        exit_code
    );

    // Verify success indicators in logs
    assert!(
        logs.contains("All CRUD operations successful"),
        "Logs should indicate CRUD operations succeeded"
    );
    assert!(logs.contains("Secret stored"), "Logs should show secret was stored");
    assert!(logs.contains("Secret resolved"), "Logs should show secret was resolved");
    assert!(logs.contains("Secret removed"), "Logs should show secret was removed");

    // Cleanup
    kubectl_delete_pod(E2E_NAMESPACE, &pod_name)?;

    Ok(())
}
