"""Background worker: analyse queued URLs with the 9B-1 engine at a safe rate.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Where it runs (viva): an asyncio task INSIDE the API process, started by the app's
lifespan. Chosen over a separate ``run_worker.py`` process because
- the models are loaded ONCE (XLM-R alone is ~1 GB of RAM; a second process would load
  a second copy) and the worker uses the same ``AnalysisEngine`` as ``/analyze``;
- the live feed (SSE) is fed directly by the in-process event bus;
- one thing to start and monitor. The queue lives in SQLite, not in memory, so nothing
  is lost when the process stops: on start, jobs left "running" go back to the queue.
CPU-heavy analysis runs in a worker thread (``asyncio.to_thread``), so the event loop
keeps answering HTTP requests while pages are analysed.

Politeness and safety: at most ``concurrency`` jobs at once and at most
``jobs_per_second`` job starts per second (configs/ingest.yaml); the 9B-1 fetcher adds
its own global and per-host limits and the SSRF guard. Every job has a time budget.

Retries: only TRANSIENT fetch problems are retried, with exponential backoff
(timeout, connection error, HTTP 5xx / 429). A 404, an SSRF refusal or a finished
analysis is final. After ``max_attempts`` the job is marked ``failed``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Protocol

from c2_analyzer.fusion.orchestrator import BudgetExceeded
from c2_analyzer.ingest.config import IngestConfig, ingest_config
from c2_analyzer.ingest.service import JOB_SOURCE_TO_REQUEST, IngestService
from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse
from c2_analyzer.schemas.ingest import WorkerStatus
from c2_analyzer.store.repository import Job

log = logging.getLogger(__name__)

MODELS_RETRY_SECONDS = 30.0


class Engine(Protocol):
    """What the worker needs from ``api.dependencies.AnalysisEngine``."""

    def get(self) -> Any: ...  # an object with analyze(request, budget) -> AnalysisResponse


class ModelsUnavailable(Exception):
    pass


def is_transient(response: AnalysisResponse) -> bool:
    """True if trying again later may succeed (network hiccup, overloaded server)."""
    if response.status != "unreachable":
        return False
    if any(finding.id == "fetch.blocked" for finding in response.findings):
        return False  # SSRF refusal: will never change
    reason = (response.status_reason or "").lower()
    if "redirect" in reason:
        return False  # too many redirects: a loop, not a hiccup
    status = response.input.http_status
    return status is None or status >= 500 or status == 429


class IngestWorker:
    """Claims queued jobs and analyses them (``start`` / ``stop`` from the app lifespan)."""

    def __init__(
        self,
        service: IngestService,
        engine: Engine,
        config: IngestConfig | None = None,
        enabled: bool = True,
    ) -> None:
        self.service = service
        self.store = service.store
        self.engine = engine
        self.config = config or ingest_config()
        self.enabled = enabled
        self._task: asyncio.Task | None = None
        self._jobs: set[asyncio.Task] = set()
        self._wake: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._state = "stopped" if enabled else "disabled"
        self.processed = self.retried = self.failed = 0
        self.last_finished_at: str | None = None
        self.last_error: str | None = None
        self.sleep: Callable[[float], Any] = asyncio.sleep  # tests may speed this up

    # ---- lifecycle ---------------------------------------------------------------------

    async def start(self) -> int:
        """Re-queue jobs a previous run left 'running', then begin. Returns that number."""
        if not self.enabled or self.running:
            return 0
        recovered = await asyncio.to_thread(self.store.requeue_running)
        if recovered:
            log.info("re-queued %d job(s) left running by the previous run", recovered)
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        self.service.on_enqueued = self.wake
        self._state = "idle"
        self._task = asyncio.create_task(self._run(), name="c2-ingest-worker")
        return recovered

    async def stop(self) -> None:
        """Cancel the loop and the in-flight jobs. A job whose analysis thread is still
        running stays 'running' in the DB and is re-queued on the next start."""
        if self._task is None:
            return
        self._task.cancel()
        for task in list(self._jobs):
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        await asyncio.gather(*self._jobs, return_exceptions=True)
        self._task = None
        self.service.on_enqueued = None
        self._state = "stopped"

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def wake(self) -> None:
        """New work arrived (thread-safe): skip the idle wait."""
        if self._loop is not None and self._wake is not None:
            with contextlib.suppress(RuntimeError):
                self._loop.call_soon_threadsafe(self._wake.set)

    def status(self) -> WorkerStatus:
        return WorkerStatus(
            enabled=self.enabled,
            running=self.running,
            state=self._state if self.running or not self.enabled else "stopped",
            concurrency=self.config.concurrency,
            jobs_per_second=self.config.jobs_per_second,
            in_flight=len(self._jobs),
            processed=self.processed,
            retried=self.retried,
            failed=self.failed,
            last_finished_at=self.last_finished_at,
            last_error=self.last_error,
        )

    # ---- main loop ---------------------------------------------------------------------

    async def _run(self) -> None:
        slots = asyncio.Semaphore(self.config.concurrency)
        interval = 1.0 / self.config.jobs_per_second
        while True:
            await slots.acquire()
            try:
                job = await asyncio.to_thread(self.store.claim_next)
            except Exception as error:  # noqa: BLE001 - e.g. database locked: try again
                slots.release()
                self.last_error = f"queue: {type(error).__name__}: {error}"
                log.exception("could not claim a job")
                await self.sleep(self.config.idle_poll_seconds)
                continue
            if job is None:
                slots.release()
                if not self._jobs:
                    self._state = "idle"
                await self._idle()
                continue
            self._state = "busy"
            task = asyncio.create_task(self._process(job, slots), name=f"c2-job-{job.id}")
            self._jobs.add(task)
            task.add_done_callback(self._jobs.discard)
            await self.sleep(interval)  # rate limit: next job start not before this

    async def _idle(self) -> None:
        assert self._wake is not None
        self._wake.clear()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._wake.wait(), timeout=self.config.idle_poll_seconds)

    async def _process(self, job: Job, slots: asyncio.Semaphore) -> None:
        try:
            await self._analyze(job)
        except ModelsUnavailable as error:
            # Not the URL's fault: give the job back without counting the attempt.
            self._state = "waiting_for_models"
            self.last_error = str(error)
            await asyncio.to_thread(self.store.release, job.id)
            await self.sleep(MODELS_RETRY_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - one bad job must not stop the worker
            log.exception("job %s crashed", job.id)
            await self._retry_or_fail(job, f"{type(error).__name__}: {error}")
        finally:
            slots.release()

    async def _analyze(self, job: Job) -> None:
        try:
            orchestrator = await asyncio.to_thread(self.engine.get)
        except RuntimeError as error:
            raise ModelsUnavailable(f"models not loaded: {error}") from None
        request = AnalysisRequest(
            url=job.url,
            source=JOB_SOURCE_TO_REQUEST.get(job.source, "api"),
            request_id=f"job-{job.id}",
        )
        budget = self.config.job_time_budget_seconds
        try:
            # The engine checks the budget between steps; wait_for is the hard stop for a
            # step that hangs (its thread finishes in the background, result ignored).
            response = await asyncio.wait_for(
                asyncio.to_thread(orchestrator.analyze, request, budget), timeout=budget + 15
            )
        except (BudgetExceeded, TimeoutError):
            await self._fail(job, f"time budget of {budget:.0f}s exceeded")
            return
        if is_transient(response):
            await self._retry_or_fail(job, response.status_reason or "unreachable")
            return
        await asyncio.to_thread(self.service.record_job_result, job.id, response, job.source)
        self.processed += 1
        self.last_finished_at = self.store.now()

    async def _retry_or_fail(self, job: Job, error: str) -> None:
        if job.attempts < self.config.max_attempts:
            wait = self.config.backoff(job.attempts)
            when = self.store.clock() + timedelta(seconds=wait)
            await asyncio.to_thread(self.store.retry_later, job.id, error, when)
            self.retried += 1
            log.info("job %s: %s - retry %d in %.0fs", job.id, error, job.attempts + 1, wait)
        else:
            await self._fail(job, f"gave up after {job.attempts} attempt(s): {error}")

    async def _fail(self, job: Job, error: str) -> None:
        await asyncio.to_thread(self.store.fail, job.id, error)
        self.failed += 1
        self.last_error = f"job {job.id}: {error}"
