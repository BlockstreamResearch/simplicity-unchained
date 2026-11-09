use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{FromRequestParts, Request},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::handlers::{ErrorResponse, SignerState};

pub(crate) const MAX_BLOCKING_JOBS: usize = 2;
pub(crate) const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WORK_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct WorkPermit(OwnedSemaphorePermit);

pub(crate) async fn request_deadline(request: Request, next: Next) -> Response {
    match tokio::time::timeout(WORK_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => WorkError::TimedOut.into_response(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkError {
    #[error("CPU work admission unavailable: {0}")]
    Unavailable(TryAcquireError),
    #[error("CPU work exceeded the response deadline")]
    TimedOut,
    #[error("CPU worker failed: {0}")]
    WorkerFailed(tokio::task::JoinError),
}

impl IntoResponse for WorkError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "Service busy; retry later"),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "Request processing timed out"),
            Self::WorkerFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Request processing failed",
            ),
        };
        log::error!("[{}] {}", status.as_u16(), self);
        (
            status,
            Json(ErrorResponse {
                error: message.to_string(),
            }),
        )
            .into_response()
    }
}

impl FromRequestParts<SignerState> for WorkPermit {
    type Rejection = WorkError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &SignerState,
    ) -> Result<Self, Self::Rejection> {
        Self::acquire(Arc::clone(&state.work_slots))
    }
}

impl WorkPermit {
    fn acquire(slots: Arc<Semaphore>) -> Result<Self, WorkError> {
        slots
            .try_acquire_owned()
            .map(Self)
            .map_err(WorkError::Unavailable)
    }

    pub(crate) async fn run<T: Send + 'static>(
        self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, WorkError> {
        self.run_with_timeout(WORK_TIMEOUT, job).await
    }

    async fn run_with_timeout<T: Send + 'static>(
        self,
        timeout: Duration,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, WorkError> {
        let mut task = tokio::task::spawn_blocking(move || {
            // A response timeout cannot stop running blocking work. Keep its slot until it exits.
            let _permit = self.0;
            job()
        });
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(result) => result.map_err(WorkError::WorkerFailed),
            Err(_) => {
                task.abort();
                Err(WorkError::TimedOut)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::sync::oneshot;

    #[test]
    fn admission_never_queues() {
        let slots = Arc::new(Semaphore::new(MAX_BLOCKING_JOBS));
        let first = WorkPermit::acquire(Arc::clone(&slots)).unwrap();
        let second = WorkPermit::acquire(Arc::clone(&slots)).unwrap();
        assert!(matches!(
            WorkPermit::acquire(Arc::clone(&slots)),
            Err(WorkError::Unavailable(_))
        ));
        drop(first);
        assert!(WorkPermit::acquire(Arc::clone(&slots)).is_ok());
        drop(second);
        assert_eq!(slots.available_permits(), MAX_BLOCKING_JOBS);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_job_does_not_block_the_async_worker() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = WorkPermit::acquire(Arc::clone(&slots)).unwrap();
        let (started, ready) = oneshot::channel();
        let (release, wait) = mpsc::channel();
        let job = tokio::spawn(permit.run(move || {
            started.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(2)).unwrap();
            42
        }));
        tokio::time::timeout(Duration::from_secs(1), ready)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slots.available_permits(), 0);
        tokio::time::timeout(Duration::from_millis(100), tokio::task::yield_now())
            .await
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(job.await.unwrap().unwrap(), 42);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn timeout_and_request_cancellation_keep_running_work_admitted() {
        for cancel in [false, true] {
            let slots = Arc::new(Semaphore::new(1));
            let permit = WorkPermit::acquire(Arc::clone(&slots)).unwrap();
            let (started, ready) = oneshot::channel();
            let (release, wait) = mpsc::channel();
            let job = tokio::spawn(permit.run_with_timeout(
                Duration::from_millis(100),
                move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(2)).unwrap();
                },
            ));
            tokio::time::timeout(Duration::from_secs(1), ready)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                job.abort();
                assert!(job.await.unwrap_err().is_cancelled());
            } else {
                let error = job.await.unwrap().unwrap_err();
                assert_eq!(error.into_response().status(), StatusCode::GATEWAY_TIMEOUT);
            }
            assert!(matches!(
                WorkPermit::acquire(Arc::clone(&slots)),
                Err(WorkError::Unavailable(_))
            ));
            release.send(()).unwrap();
            let returned =
                tokio::time::timeout(Duration::from_secs(1), Arc::clone(&slots).acquire_owned())
                    .await
                    .unwrap()
                    .unwrap();
            drop(returned);
            assert_eq!(slots.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn worker_failure_is_reported_and_releases_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let error = WorkPermit::acquire(Arc::clone(&slots))
            .unwrap()
            .run(|| panic!("test worker failure"))
            .await
            .unwrap_err();
        assert!(matches!(error, WorkError::WorkerFailed(_)));
        assert_eq!(
            error.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(slots.available_permits(), 1);
    }
}
