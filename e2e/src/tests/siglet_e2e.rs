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

//! E2E tests for Siglet DataFlow handler
//!
//! These tests deploy Siglet in a Kind cluster and verify its DataFlow
//! handling capabilities, including signaling API interactions and health endpoints.
//!
//! Note: These tests share a single Siglet deployment and can run in parallel.

use crate::utils::*;
use anyhow::{Context, Result};
use dsdk_facet_testcontainers::utils::get_available_port;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Shared Siglet deployment state
static SIGLET_DEPLOYMENT: OnceCell<Arc<SigletDeployment>> = OnceCell::const_new();

/// Test that Siglet deploys successfully and responds to health checks
#[tokio::test]
#[ignore]
async fn test_siglet_deployment_and_health() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    let pod_name = &deployment.pod_name;

    // Test health endpoint using kubectl exec
    let health_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/health"],
    )?;

    // Verify health response contains expected status
    assert!(
        health_response.contains("healthy"),
        "Health endpoint should return healthy status"
    );

    // Test root endpoint
    let root_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/"],
    )?;

    // Verify root response contains expected metadata
    assert!(
        root_response.contains("Siglet"),
        "Root endpoint should return Siglet metadata"
    );
    assert!(root_response.contains("version"), "Root endpoint should return version");
    assert!(
        root_response.contains("running"),
        "Root endpoint should indicate running status"
    );

    let logs = get_pod_logs(E2E_NAMESPACE, pod_name, "siglet")?;
    // println!("Siglet logs:\n{}", logs);

    // Verify startup messages in logs
    assert!(logs.contains("Siglet API"), "Logs should indicate Siglet API started");
    assert!(
        logs.contains("Signaling API"),
        "Logs should indicate Signaling API started"
    );
    assert!(logs.contains("Ready"), "Logs should indicate Siglet is ready");

    Ok(())
}

/// Test consumer-provider pull interaction
///
/// This test verifies the complete pull transfer flow:
/// - Consumer calls prepare endpoint (no data address returned)
/// - Provider calls start endpoint and returns data address with tokens
/// - Consumer calls started endpoint with provider's data address
/// - Provider terminates the transfer
#[tokio::test]
#[ignore]
async fn test_pull_operations() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;

    // Get the port-forwarded URL for the Signaling API
    let signaling_url = format!("http://localhost:{}", deployment.signaling_port);

    // Create HTTP client
    let client = Client::new();

    // Step 1: Consumer calls prepare endpoint
    println!("Step 1: Consumer calling prepare endpoint");
    let prepare_message = serde_json::json!({
        "datasetId": "test-dataset-123",
        "participantId": "did:web:consumer.example.com",
        "processId": "test-consumer-process-456",
        "agreementId": "test-agreement-789",
        "transferType": "http-pull",
        "dataspaceContext": "test-dataspace",
        "callbackAddress": "https://consumer.example.com/callback",
        "messageId": "msg-prepare-001",
        "counterPartyId": "did:web:provider.example.com",
        "labels": [],
        "metadata": {},
    });

    let prepare_response = client
        .post(format!("{}/api/v1/dataflows/prepare", signaling_url))
        .header("Content-Type", "application/json")
        .header("X-Participant-Id", "test-participant-context")
        .json(&prepare_message)
        .send()
        .await
        .context("Failed to send prepare request")?;

    assert!(
        prepare_response.status().is_success(),
        "Prepare request should succeed, got status: {}",
        prepare_response.status()
    );

    let prepare_result: serde_json::Value = prepare_response
        .json()
        .await
        .context("Failed to parse prepare response")?;

    // Verify prepare response does NOT contain a meaningful dataAddress (it's a pull)
    // The field might be present but should be null or empty
    if let Some(data_address) = prepare_result.get("dataAddress") {
        assert!(
            data_address.is_null(),
            "Prepare response should not contain a dataAddress for pull transfers, got: {}",
            data_address
        );
    }

    // Step 2: Provider calls start endpoint
    let start_message = serde_json::json!({
        "datasetId": "test-dataset-123",
        "participantId": "did:web:provider.example.com",
        "processId": "test-provider-process-456",
        "agreementId": "test-agreement-789",
        "transferType": "http-pull",
        "dataspaceContext": "test-dataspace",
        "callbackAddress": "https://provider.example.com/callback",
        "messageId": "msg-start-001",
        "counterPartyId": "did:web:consumer.example.com",
        "labels": [],
        "metadata": {
            "claim1": "claimvalue1",
            "claim2": "claimvalue2"
        }
    });

    let start_response = client
        .post(format!("{}/api/v1/dataflows/start", signaling_url))
        .header("Content-Type", "application/json")
        .header("X-Participant-Id", "test-participant-context")
        .json(&start_message)
        .send()
        .await
        .context("Failed to send start request")?;

    assert!(
        start_response.status().is_success(),
        "Start request should succeed, got status: {}",
        start_response.status()
    );

    let start_result: serde_json::Value = start_response.json().await.context("Failed to parse start response")?;

    // Verify the response contains expected fields
    assert!(
        start_result.get("state").is_some(),
        "Response should contain 'state' field"
    );
    assert!(
        start_result.get("dataplaneId").is_some(),
        "Response should contain 'dataplaneId' field"
    );

    let state = start_result["state"].as_str().unwrap();

    // The state should be "STARTED" for http-pull transfers with token provider
    assert_eq!(state, "STARTED", "DataFlow should be in STARTED state");

    // Check if data address was returned with auth properties
    let data_address = start_result.get("dataAddress").unwrap();

    let properties = data_address.get("endpointProperties").unwrap();
    let properties_array = properties.as_array().unwrap();

    let has_auth = properties_array
        .iter()
        .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("authorization"));
    assert!(has_auth, "Authorization property not found in data address");

    // Extract the JWT token for inspection
    let auth_prop = properties_array
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("authorization"))
        .unwrap();

    let token = auth_prop.get("value").and_then(|v| v.as_str()).unwrap();
    assert!(!token.is_empty());

    // Decode and parse the JWT
    let token_parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        token_parts.len(),
        3,
        "JWT should have 3 parts (header.payload.signature)"
    );

    // Decode the payload (second part) from base64
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(token_parts[1])
        .context("Failed to decode JWT payload")?;
    let payload_str = String::from_utf8(payload_bytes).context("Failed to convert payload to string")?;
    let jwt_payload: serde_json::Value =
        serde_json::from_str(&payload_str).context("Failed to parse JWT payload as JSON")?;

    // Verify the metadata claims are present in the JWT
    assert_eq!(
        jwt_payload.get("claim1").and_then(|v| v.as_str()),
        Some("claimvalue1"),
        "claim1 should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get("claim2").and_then(|v| v.as_str()),
        Some("claimvalue2"),
        "claim2 should be present in JWT with correct value"
    );

    // Check for refresh token
    let has_refresh = properties_array
        .iter()
        .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("refreshToken"));
    assert!(has_refresh, "Refresh token not found in data address");

    // Check for refresh endpoint
    let has_endpoint = properties_array
        .iter()
        .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("refreshEndpoint"));
    assert!(has_endpoint, "Refresh Endpoint not found in data address");

    // Step 3: Consumer calls started endpoint with provider's data address
    let started_message = serde_json::json!({
        "participantId": "did:web:consumer.example.com",
        "counterPartyId": "did:web:provider.example.com",
        "dataAddress": data_address,
        "messageId": "msg-started-001"
    });

    let consumer_flow_id = "test-consumer-process-456";

    let started_response = client
        .post(format!(
            "{}/api/v1/dataflows/{}/started",
            signaling_url, consumer_flow_id
        ))
        .header("Content-Type", "application/json")
        .header("X-Participant-Id", "test-participant-context")
        .json(&started_message)
        .send()
        .await
        .context("Failed to send started request")?;

    let status = started_response.status();
    if !status.is_success() {
        let error_body = started_response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read error body".to_string());
        panic!(
            "Started request should succeed, got status: {}, body: {}",
            status, error_body
        );
    }

    // Step 4: Provider terminates the transfer
    let terminate_message = serde_json::json!({
        "reason": "Test termination"
    });

    let provider_flow_id = "test-provider-process-456";

    let terminate_response = client
        .post(format!(
            "{}/api/v1/dataflows/{}/terminate",
            signaling_url, provider_flow_id
        ))
        .header("Content-Type", "application/json")
        .header("X-Participant-Id", "test-participant-context")
        .json(&terminate_message)
        .send()
        .await
        .context("Failed to send terminate request")?;

    assert!(
        terminate_response.status().is_success(),
        "Terminate should return 200 OK for successful termination, got: {}",
        terminate_response.status()
    );

    Ok(())
}

/// Information about the deployed Siglet instance
struct SigletDeployment {
    pod_name: String,
    signaling_port: u16,
}

/// Sets up port forwarding for the Signaling API and returns the local port
async fn setup_signaling_port_forward() -> Result<u16> {
    // Get an available port on the host machine
    let local_port = get_available_port();

    // Start port-forward in background
    let _child = std::process::Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            E2E_NAMESPACE,
            "service/siglet",
            &format!("{}:8081", local_port),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start port-forward")?;

    // Wait for port-forward to establish
    let client = Client::new();
    let start = std::time::Instant::now();
    let timeout_secs = 10;

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            anyhow::bail!(
                "Failed to establish port-forward connection after {} seconds",
                timeout_secs
            );
        }

        if client
            .get(format!("http://localhost:{}/api/v1/dataflows", local_port))
            .timeout(tokio::time::Duration::from_secs(1))
            .send()
            .await
            .is_ok()
        {
            return Ok(local_port);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
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

    Ok(())
}

/// Deploys the Siglet to K8S
/// This function is idempotent and thread-safe - multiple tests can call it concurrently
async fn ensure_siglet_deployed() -> Result<Arc<SigletDeployment>> {
    SIGLET_DEPLOYMENT
        .get_or_try_init(|| async {
            verify_e2e_setup().await?;

            let config_manifest = "manifests/siglet-config.yaml";
            let deployment_manifest = "manifests/siglet-deployment.yaml";
            let service_manifest = "manifests/siglet-service.yaml";

            println!("Preparing Siglet deployment");

            // Clean up any existing deployment
            let _ = kubectl_delete(deployment_manifest);
            let _ = kubectl_delete(service_manifest);
            let _ = kubectl_delete(config_manifest);

            // Wait for pods to actually be deleted instead of fixed sleep
            // Wait up to 60s — Kubernetes default graceful termination period is 30s,
            // so waiting only 30s would race against a pod that just started terminating.
            wait_for_pods_deleted_by_label(E2E_NAMESPACE, "app=siglet", 60)
                .await
                .context("Failed to wait for previous Siglet pods to be deleted")?;

            // Deploy Siglet (uses Vault Agent sidecar pattern)
            // Tolerate AlreadyExists: a concurrent retry process may have deployed first
            println!("Deploying Siglet with Vault Agent sidecar");
            for manifest in [config_manifest, deployment_manifest, service_manifest] {
                if let Err(e) = kubectl_apply(manifest) {
                    if !e.to_string().contains("AlreadyExists") {
                        return Err(e);
                    }
                }
            }

            // Wait for deployment to be ready
            println!("Waiting for Siglet to be ready");
            wait_for_deployment_ready(E2E_NAMESPACE, "siglet", 120).await?;
            // Wait for pod to be ready
            wait_for_pod_ready(E2E_NAMESPACE, "app=siglet", 120).await?;

            // Get pod name
            let pod_name_output = std::process::Command::new("kubectl")
                .args([
                    "get",
                    "pods",
                    "-n",
                    E2E_NAMESPACE,
                    "-l",
                    "app=siglet",
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                ])
                .output()
                .context("Failed to get pod name")?;
            let pod_name = String::from_utf8_lossy(&pod_name_output.stdout).to_string();

            println!("Siglet deployed: pod={}", pod_name);

            // Set up port-forward for Signaling API
            let signaling_port = setup_signaling_port_forward().await?;

            Ok(Arc::new(SigletDeployment {
                pod_name,
                signaling_port,
            }))
        })
        .await
        .map(|arc| arc.clone())
}
