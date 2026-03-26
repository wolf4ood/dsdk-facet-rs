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

#![allow(clippy::unwrap_used)]

use crate::handler::SigletDataFlowHandler;
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_flow::DataFlow;
use dsdk_facet_core::token::MemoryTokenStore;
use std::collections::HashSet;
use std::sync::Arc;

/// Helper function to create a test DataFlow with required fields
fn create_test_flow(id: &str, participant_id: &str, transfer_type: &str) -> DataFlow {
    DataFlow::builder()
        .id(id)
        .participant_id(participant_id)
        .transfer_type(transfer_type)
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .build()
}

#[tokio::test]
async fn test_can_handle_with_no_transfer_types_accepts_all() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let handler = SigletDataFlowHandler::new(token_store);

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_matching_transfer_type_accepts() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let mut transfer_types = HashSet::new();
    transfer_types.insert("http-pull".to_string());
    transfer_types.insert("http-push".to_string());

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .transfer_types(transfer_types)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_non_matching_transfer_type_rejects() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let mut transfer_types = HashSet::new();
    transfer_types.insert("http-pull".to_string());
    transfer_types.insert("http-push".to_string());

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .transfer_types(transfer_types)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "UnknownData");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_single_transfer_type() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let mut transfer_types = HashSet::new();
    transfer_types.insert("http-pull".to_string());

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .transfer_types(transfer_types)
        .build();

    // Should accept http-pull
    let flow1 = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow1).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should reject http-push
    let flow2 = create_test_flow("flow-2", "participant-1", "http-push");

    let result = handler.can_handle(&flow2).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
