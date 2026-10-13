//! Prepare and verify anchor DA before starting database writes.
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, ensure};
use ream_consensus_beacon::{
    blob_sidecar::BlobSidecar,
    data_column_sidecar::{DataColumnSidecar, get_data_column_sidecars_from_block},
    electra::beacon_block::SignedBeaconBlock,
    matrix_entry::{compute_cells_and_kzg_proofs, das_context},
};
use ream_consensus_misc::misc::compute_epoch_at_slot;
use ream_execution_rpc_types::get_blobs::Blob;
use ream_network_spec::networks::{BeaconNetworkSpec, beacon_network_spec};
use ream_polynomial_commitments::handlers::{
    verify_blob_kzg_proof_batch, verify_data_column_sidecar_kzg_proofs,
};
use reqwest::{Url, header::ACCEPT};
use serde::Deserialize;

#[derive(Default)]
pub(crate) struct AnchorData {
    pub blobs: Vec<BlobSidecar>,
    pub columns: Vec<DataColumnSidecar>,
}

#[derive(Deserialize)]
struct Response<T> {
    data: Vec<T>,
}

pub(crate) async fn fetch_anchor_data_from_sources(
    sources: &[Url],
    block: &SignedBeaconBlock,
    genesis_time: u64,
) -> anyhow::Result<AnchorData> {
    let spec = beacon_network_spec();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let current_epoch =
        compute_epoch_at_slot(now.saturating_sub(genesis_time) / spec.seconds_per_slot());
    fetch_from_sources_at(sources, block, &spec, current_epoch).await
}

async fn fetch_from_sources_at(
    sources: &[Url],
    block: &SignedBeaconBlock,
    spec: &BeaconNetworkSpec,
    current_epoch: u64,
) -> anyhow::Result<AnchorData> {
    let mut failures = Vec::new();
    for source in sources {
        match fetch_anchor_data_at(source, block, spec, current_epoch).await {
            Ok(data) => return Ok(data),
            Err(err) => {
                tracing::warn!(%source, %err, "Anchor DA unavailable; trying next checkpoint source");
                failures.push(format!("{source}: {err:#}"));
            }
        }
    }
    anyhow::bail!(
        "No checkpoint source could provide verified DA for anchor {}. For post-Fulu checkpoints with blobs, --checkpoint-sync-url must serve /eth/v1/beacon/blobs/{{block_root}}; use a blob-capable provider. Bootstrap has not been completed. Errors: {}",
        block.message.block_root(),
        failures.join("; ")
    )
}

async fn fetch_anchor_data_at(
    url: &Url,
    block: &SignedBeaconBlock,
    spec: &BeaconNetworkSpec,
    current_epoch: u64,
) -> anyhow::Result<AnchorData> {
    let epoch = compute_epoch_at_slot(block.message.slot);
    let commitments = &block.message.body.blob_kzg_commitments;
    if commitments.is_empty() {
        return Ok(AnchorData::default());
    }
    let root = block.message.block_root();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    if epoch < spec.fulu_fork_epoch {
        if epoch < current_epoch.saturating_sub(spec.min_epochs_for_blob_sidecars_requests) {
            return Ok(AnchorData::default());
        }
        let mut blobs = client
            .get(url.join(&format!("eth/v1/beacon/blob_sidecars/{root}"))?)
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .error_for_status()?
            .json::<Response<BlobSidecar>>()
            .await?
            .data;
        ensure!(
            blobs.len() == commitments.len(),
            "Incomplete anchor blob sidecars"
        );
        blobs.sort_by_key(|b| b.index);
        for (index, sidecar) in blobs.iter().enumerate() {
            ensure!(
                sidecar.index == index as u64
                    && sidecar.signed_block_header == block.signed_header()
                    && sidecar.kzg_commitment == commitments[index]
                    && sidecar.verify_blob_sidecar_inclusion_proof(),
                "Anchor blob sidecar does not match block"
            );
        }
        ensure!(
            verify_blob_kzg_proof_batch(
                &blobs.iter().map(|b| b.blob.clone()).collect::<Vec<_>>(),
                commitments,
                &blobs.iter().map(|b| b.kzg_proof).collect::<Vec<_>>()
            )?,
            "Invalid anchor blob proof"
        );
        return Ok(AnchorData {
            blobs,
            columns: vec![],
        });
    }
    if epoch < current_epoch.saturating_sub(spec.min_epochs_for_data_column_sidecars_requests) {
        return Ok(AnchorData::default());
    }
    // This endpoint returns raw blobs, not BlobSidecar objects. Their order is the
    // commitment order in the anchor; recomputing commitments authenticates each blob.
    let blobs = client
        .get(url.join(&format!("eth/v1/beacon/blobs/{root}"))?)
        .header(ACCEPT, "application/json")
        .send()
        .await?
        .error_for_status()
        .context("Checkpoint provider must serve anchor blobs for post-Fulu bootstrap")?
        .json::<Response<Blob>>()
        .await?
        .data;
    Ok(AnchorData {
        blobs: vec![],
        columns: build_anchor_columns(block, &blobs)?,
    })
}

pub(crate) fn build_anchor_columns(
    block: &SignedBeaconBlock,
    blobs: &[Blob],
) -> anyhow::Result<Vec<DataColumnSidecar>> {
    let commitments = &block.message.body.blob_kzg_commitments;
    ensure!(
        blobs.len() == commitments.len(),
        "Incomplete anchor blobs: expected {}, received {}",
        commitments.len(),
        blobs.len()
    );
    let context = das_context();
    let mut cells = Vec::with_capacity(blobs.len());
    for (blob, commitment) in blobs.iter().zip(commitments) {
        let computed = context
            .blob_to_kzg_commitment(&blob.to_fixed_bytes())
            .map_err(|err| anyhow::anyhow!("Invalid blob: {err:?}"))?;
        ensure!(computed == commitment.0, "Anchor blob commitment mismatch");
        cells.push(compute_cells_and_kzg_proofs(blob, context)?);
    }
    let columns = get_data_column_sidecars_from_block(block, cells)?;
    for column in &columns {
        ensure!(
            column.signed_block_header == block.signed_header()
                && column.kzg_commitments == *commitments
                && column.verify_inclusion_proof(),
            "Invalid anchor column inclusion proof"
        );
        ensure!(
            verify_data_column_sidecar_kzg_proofs(column)?,
            "Invalid anchor column KZG proof"
        );
    }
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::electra::beacon_block::BeaconBlock;
    use ream_consensus_misc::{
        constants::beacon::SLOTS_PER_EPOCH, polynomial_commitments::kzg_commitment::KZGCommitment,
    };
    use ream_network_spec::networks::{DEV, initialize_test_network_spec};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    fn fixture() -> (SignedBeaconBlock, Blob) {
        initialize_test_network_spec();
        let blob = Blob::default();
        let commitment = KZGCommitment(
            das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .unwrap(),
        );
        let mut block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 64 * SLOTS_PER_EPOCH,
                ..Default::default()
            },
            signature: Default::default(),
        };
        block
            .message
            .body
            .blob_kzg_commitments
            .push(commitment)
            .unwrap();
        (block, blob)
    }

    async fn server(
        path: String,
        status: u16,
        body: Vec<u8>,
    ) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with(&format!("GET {path} HTTP/1.1"))
            );
            socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn post_fulu_anchor_blobs_build_all_verified_columns() {
        let (block, blob) = fixture();
        let mut spec = (**DEV).clone();
        spec.fulu_fork_epoch = 0;
        spec.min_epochs_for_data_column_sidecars_requests = 4;
        let body = serde_json::to_vec(&serde_json::json!({"data": [blob]})).unwrap();
        let (url, server) = server(
            format!("/eth/v1/beacon/blobs/{}", block.message.block_root()),
            200,
            body,
        )
        .await;
        // Equality at the retention boundary still requires DA.
        let data = fetch_anchor_data_at(&url, &block, &spec, 68).await.unwrap();
        server.await.unwrap();
        assert_eq!(data.columns.len(), 128);
        let dir = std::env::temp_dir().join(format!(
            "ream_anchor_columns_{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = ream_storage::db::ReamDB::new(dir.clone())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        use ream_storage::tables::table::CustomTable;
        for (index, column) in data.columns.iter().enumerate() {
            assert_eq!(column.index, index as u64);
            assert!(column.verify_inclusion_proof());
            assert!(verify_data_column_sidecar_kzg_proofs(column).unwrap());
            let id = ream_consensus_beacon::data_column_sidecar::ColumnIdentifier::new(
                block.message.block_root(),
                column.index,
            );
            db.column_sidecars_provider()
                .insert(id, column.clone())
                .unwrap();
            assert_eq!(
                db.column_sidecars_provider().get(id).unwrap(),
                Some(column.clone())
            );
        }
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn unavailable_or_incomplete_anchor_blobs_fail() {
        let (block, _) = fixture();
        let mut spec = (**DEV).clone();
        spec.fulu_fork_epoch = 0;
        for (status, body) in [
            (404, b"missing".to_vec()),
            (200, br#"{"data":[]}"#.to_vec()),
        ] {
            let (url, server) = server(
                format!("/eth/v1/beacon/blobs/{}", block.message.block_root()),
                status,
                body,
            )
            .await;
            assert!(fetch_anchor_data_at(&url, &block, &spec, 64).await.is_err());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn fallback_keeps_the_same_anchor_and_rejects_incomplete_data() {
        let (block, blob) = fixture();
        let mut spec = (**DEV).clone();
        spec.fulu_fork_epoch = 0;
        let path = format!("/eth/v1/beacon/blobs/{}", block.message.block_root());
        let (missing, first) = server(path.clone(), 404, b"missing".to_vec()).await;
        let (incomplete, second) = server(path.clone(), 200, br#"{"data":[]}"#.to_vec()).await;
        let (valid, third) = server(
            path,
            200,
            serde_json::to_vec(&serde_json::json!({"data":[blob]})).unwrap(),
        )
        .await;
        let data = fetch_from_sources_at(&[missing, incomplete, valid], &block, &spec, 64)
            .await
            .unwrap();
        first.await.unwrap();
        second.await.unwrap();
        third.await.unwrap();
        assert_eq!(data.columns.len(), 128);
        assert!(
            data.columns
                .iter()
                .all(|column| column.signed_block_header == block.signed_header())
        );
    }

    #[tokio::test]
    async fn pre_fulu_anchor_sidecars_require_matching_header_and_proof() {
        let (block, blob) = fixture();
        let mut spec = (**DEV).clone();
        spec.fulu_fork_epoch = u64::MAX;
        // For the zero polynomial both the commitment and blob proof are infinity.
        let blob_and_proof = ream_execution_rpc_types::get_blobs::BlobAndProofV1 {
            blob,
            proof: block.message.body.blob_kzg_commitments[0].0.into(),
        };
        let sidecar = block.blob_sidecar(blob_and_proof, 0).unwrap();
        for valid in [true, false] {
            let mut candidate = sidecar.clone();
            if !valid {
                candidate.kzg_commitment_inclusion_proof[0] =
                    alloy_primitives::B256::repeat_byte(1);
            }
            let body = serde_json::to_vec(&serde_json::json!({"data": [candidate]})).unwrap();
            let (url, server) = server(
                format!(
                    "/eth/v1/beacon/blob_sidecars/{}",
                    block.message.block_root()
                ),
                200,
                body,
            )
            .await;
            let result = fetch_anchor_data_at(&url, &block, &spec, 64).await;
            server.await.unwrap();
            if valid {
                let data = result.unwrap();
                assert_eq!(data.blobs, vec![sidecar.clone()]);
                assert!(data.columns.is_empty());
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn outside_retention_or_no_commitments_needs_no_provider() {
        let (mut block, _) = fixture();
        let mut spec = (**DEV).clone();
        spec.fulu_fork_epoch = 0;
        spec.min_epochs_for_data_column_sidecars_requests = 4;
        let url = "http://127.0.0.1:1/".parse().unwrap();
        assert!(
            fetch_anchor_data_at(&url, &block, &spec, 69)
                .await
                .unwrap()
                .columns
                .is_empty()
        );
        block.message.body.blob_kzg_commitments = Default::default();
        assert!(
            fetch_anchor_data_at(&url, &block, &spec, 64)
                .await
                .unwrap()
                .columns
                .is_empty()
        );
    }

    #[test]
    fn wrong_or_extra_blobs_cannot_produce_anchor_columns() {
        let (block, mut blob) = fixture();
        assert!(build_anchor_columns(&block, &[blob.clone(), blob.clone()]).is_err());
        blob.inner[31] = 1;
        assert!(build_anchor_columns(&block, &[blob]).is_err());
    }
}
