pub mod attestation;
pub mod blob_sidecar;
pub mod block;
pub mod committee;
pub mod config;
pub mod debug;
pub mod duties;
pub mod events;
pub mod header;
pub mod health;
pub mod identity;
pub mod light_client;
pub mod peers;
pub mod pool;
pub mod prepare_beacon_proposer;
pub mod state;
pub mod syncing;
pub mod validator;

mod representation;
use alloy_primitives::aliases::B32;
use ream_api_types_common::error::ApiError;
use ream_consensus_misc::constants::beacon::genesis_validators_root;
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::{db::beacon::BeaconDB, tables::field::REDBField};

/// The fork digest to publish gossip with now, on the chain's clock.
pub(crate) fn gossip_fork_digest(db: &BeaconDB) -> Result<B32, ApiError> {
    let genesis_time = db
        .genesis_time_provider()
        .get()
        .map_err(|err| ApiError::InternalError(format!("Failed to get genesis time: {err:?}")))?;
    Ok(beacon_network_spec().current_fork_digest(genesis_time, genesis_validators_root()))
}

/// Heavy tasks that may run at once. Each can hold a rebuilt beacon state in memory.
const MAX_HEAVY_TASKS: usize = 2;
static HEAVY_TASKS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_HEAVY_TASKS);

/// Runs `work` on actix's blocking pool, at most `MAX_HEAVY_TASKS` at a time. Rewards read and
/// rebuild states for seconds; run on the HTTP worker thread they stall every other connection on
/// it, which then gets 408.
pub(crate) async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    run_limited(&HEAVY_TASKS, work).await
}

async fn run_limited<T: Send + 'static>(
    limit: &'static tokio::sync::Semaphore,
    work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let permit = limit
        .acquire()
        .await
        .map_err(|err| ApiError::InternalError(format!("Heavy task limit closed: {err}")))?;
    actix_web::web::block(move || {
        // Held by the work, which keeps running if the request is dropped meanwhile.
        let _permit = permit;
        work()
    })
    .await
    .map_err(|err| ApiError::InternalError(format!("Blocking task failed: {err}")))?
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    /// On a single-threaded runtime, a slow task run inline would hold the timer back too.
    #[tokio::test]
    async fn blocking_work_does_not_hold_the_handler_thread() {
        let start = Instant::now();
        let slow = run_blocking(|| {
            std::thread::sleep(Duration::from_millis(500));
            Ok(1)
        });
        let fast = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            start.elapsed()
        };
        let (slow, fast) = tokio::join!(slow, fast);

        assert_eq!(slow.unwrap(), 1);
        assert!(fast < Duration::from_millis(400), "timer waited {fast:?}");
    }

    #[tokio::test]
    async fn a_dropped_request_keeps_its_slot_until_the_work_ends() {
        static LIMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let start = Instant::now();
        let dropped = tokio::time::timeout(
            Duration::from_millis(50),
            run_limited(&LIMIT, || {
                std::thread::sleep(Duration::from_millis(400));
                Ok(())
            }),
        )
        .await;
        assert!(dropped.is_err());

        run_limited(&LIMIT, || Ok(())).await.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(400));
    }

    #[tokio::test]
    async fn heavy_tasks_beyond_the_limit_wait() {
        let start = Instant::now();
        let task = || {
            run_blocking(|| {
                std::thread::sleep(Duration::from_millis(300));
                Ok(())
            })
        };
        let (first, second, third) = tokio::join!(task(), task(), task());

        assert!(first.is_ok() && second.is_ok() && third.is_ok());
        assert!(start.elapsed() >= Duration::from_millis(600));
    }
}
