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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigletError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DataPlane SDK error: {0}")]
    DataPlane(String),
}
