// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressState {
    pub next_checkpoint: u64,
    pub updated_at_ms: u128,
}

impl Default for ProgressState {
    fn default() -> Self {
        Self {
            next_checkpoint: 0,
            updated_at_ms: now_ms(),
        }
    }
}

pub async fn load(path: &Path) -> anyhow::Result<ProgressState> {
    if !path.exists() {
        return Ok(ProgressState::default());
    }

    let content = fs::read_to_string(path).await?;
    let state = serde_json::from_str::<ProgressState>(&content)?;
    Ok(state)
}

pub async fn store(path: &Path, next_checkpoint: u64) -> anyhow::Result<()> {
    let state = ProgressState {
        next_checkpoint,
        updated_at_ms: now_ms(),
    };

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_vec_pretty(&state)?).await?;
    fs::rename(&tmp_path, path).await?;
    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
