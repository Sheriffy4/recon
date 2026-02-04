#!/usr/bin/env python3
"""
Workflow Scheduler

This module provides scheduling capabilities for automated workflows,
including periodic execution, event-triggered workflows, and batch processing.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

# import schedule  # Optional external dependency

from .automated_workflow import AutomatedWorkflow, WorkflowConfig, WorkflowResult
from .workflow_config_manager import WorkflowConfigManager
from .logging_config import setup_logging


@dataclass
class ScheduledJob:
    """Represents a scheduled workflow job"""

    id: str
    name: str
    config: WorkflowConfig
    schedule_type: str  # 'interval', 'daily', 'weekly', 'cron'
    schedule_params: Dict[str, Any]
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    last_result: Optional[WorkflowResult] = None


@dataclass
class BatchJob:
    """Represents a batch processing job"""

    id: str
    name: str
    pcap_pairs: List[tuple]  # List of (recon_pcap, zapret_pcap) pairs
    base_config: WorkflowConfig
    parallel_execution: bool = True
    max_concurrent: int = 3
    results: List[WorkflowResult] = field(default_factory=list)


class WorkflowScheduler:
    """
    Scheduler for automated workflows

    Provides functionality to:
    - Schedule workflows at regular intervals
    - Trigger workflows based on file changes
    - Execute batch processing jobs
    - Monitor and report on scheduled jobs
    """

    def __init__(self, scheduler_dir: str = "scheduler_data"):
        self.scheduler_dir = Path(scheduler_dir)
        self.scheduler_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(__name__)
        self.config_manager = WorkflowConfigManager()

        # Job storage
        self.scheduled_jobs: Dict[str, ScheduledJob] = {}
        self.batch_jobs: Dict[str, BatchJob] = {}

        # Scheduler state
        self.running = False
        self.scheduler_task: Optional[asyncio.Task] = None

        # Load existing jobs
        self._load_jobs()

    def add_scheduled_job(self, job: ScheduledJob) -> None:
        """Add a scheduled job"""
        self.scheduled_jobs[job.id] = job
        self._save_jobs()
        self.logger.info(f"Added scheduled job: {job.name} ({job.id})")

    def remove_scheduled_job(self, job_id: str) -> bool:
        """Remove a scheduled job"""
        if job_id in self.scheduled_jobs:
            job = self.scheduled_jobs.pop(job_id)
            self._save_jobs()
            self.logger.info(f"Removed scheduled job: {job.name} ({job_id})")
            return True
        return False

    def add_batch_job(self, job: BatchJob) -> None:
        """Add a batch processing job"""
        self.batch_jobs[job.id] = job
        self._save_jobs()
        self.logger.info(f"Added batch job: {job.name} ({job.id})")

    def remove_batch_job(self, job_id: str) -> bool:
        """Remove a batch processing job"""
        if job_id in self.batch_jobs:
            job = self.batch_jobs.pop(job_id)
            self._save_jobs()
            self.logger.info(f"Removed batch job: {job.name} ({job_id})")
            return True
        return False

    def enable_job(self, job_id: str) -> bool:
        """Enable a scheduled job"""
        if job_id in self.scheduled_jobs:
            self.scheduled_jobs[job_id].enabled = True
            self._save_jobs()
            return True
        return False

    def disable_job(self, job_id: str) -> bool:
        """Disable a scheduled job"""
        if job_id in self.scheduled_jobs:
            self.scheduled_jobs[job_id].enabled = False
            self._save_jobs()
            return True
        return False

    async def start_scheduler(self) -> None:
        """Start the scheduler"""
        if self.running:
            self.logger.warning("Scheduler is already running")
            return

        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        self.logger.info("Workflow scheduler started")

    async def stop_scheduler(self) -> None:
        """Stop the scheduler"""
        if not self.running:
            return

        self.running = False

        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass

        self.logger.info("Workflow scheduler stopped")

    async def run_job_now(self, job_id: str) -> Optional[WorkflowResult]:
        """Run a scheduled job immediately"""
        if job_id not in self.scheduled_jobs:
            self.logger.error(f"Job not found: {job_id}")
            return None

        job = self.scheduled_jobs[job_id]
        return await self._execute_scheduled_job(job)

    async def run_batch_job(self, job_id: str) -> List[WorkflowResult]:
        """Run a batch processing job"""
        if job_id not in self.batch_jobs:
            self.logger.error(f"Batch job not found: {job_id}")
            return []

        job = self.batch_jobs[job_id]
        return await self._execute_batch_job(job)

    def create_interval_job(
        self, name: str, config: WorkflowConfig, interval_minutes: int
    ) -> ScheduledJob:
        """Create a job that runs at regular intervals"""
        job_id = f"interval_{int(time.time())}_{hash(name) % 10000}"

        return ScheduledJob(
            id=job_id,
            name=name,
            config=config,
            schedule_type="interval",
            schedule_params={"minutes": interval_minutes},
            next_run=datetime.now() + timedelta(minutes=interval_minutes),
        )

    def create_daily_job(
        self, name: str, config: WorkflowConfig, hour: int = 2, minute: int = 0
    ) -> ScheduledJob:
        """Create a job that runs daily at specified time"""
        job_id = f"daily_{int(time.time())}_{hash(name) % 10000}"

        # Calculate next run time
        now = datetime.now()
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)

        return ScheduledJob(
            id=job_id,
            name=name,
            config=config,
            schedule_type="daily",
            schedule_params={"hour": hour, "minute": minute},
            next_run=next_run,
        )

    def create_weekly_job(
        self,
        name: str,
        config: WorkflowConfig,
        weekday: int = 0,
        hour: int = 2,
        minute: int = 0,
    ) -> ScheduledJob:
        """Create a job that runs weekly on specified day and time"""
        job_id = f"weekly_{int(time.time())}_{hash(name) % 10000}"

        # Calculate next run time
        now = datetime.now()
        days_ahead = weekday - now.weekday()
        if days_ahead <= 0:  # Target day already happened this week
            days_ahead += 7

        next_run = now + timedelta(days=days_ahead)
        next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)

        return ScheduledJob(
            id=job_id,
            name=name,
            config=config,
            schedule_type="weekly",
            schedule_params={"weekday": weekday, "hour": hour, "minute": minute},
            next_run=next_run,
        )

    def create_batch_job_from_directory(
        self, name: str, pcap_directory: str, base_config: WorkflowConfig
    ) -> Optional[BatchJob]:
        """Create a batch job from PCAP files in a directory"""
        pcap_dir = Path(pcap_directory)
        if not pcap_dir.exists():
            self.logger.error(f"PCAP directory not found: {pcap_directory}")
            return None

        # Find PCAP pairs
        pcap_pairs = []
        recon_files = list(pcap_dir.glob("recon_*.pcap"))

        for recon_file in recon_files:
            # Look for corresponding zapret file
            domain = recon_file.name.replace("recon_", "").replace(".pcap", "")
            zapret_file = pcap_dir / f"zapret_{domain}.pcap"

            if zapret_file.exists():
                pcap_pairs.append((str(recon_file), str(zapret_file)))

        if not pcap_pairs:
            self.logger.warning(f"No PCAP pairs found in {pcap_directory}")
            return None

        job_id = f"batch_{int(time.time())}_{hash(name) % 10000}"

        return BatchJob(id=job_id, name=name, pcap_pairs=pcap_pairs, base_config=base_config)

    async def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.running:
            try:
                current_time = datetime.now()

                # Check scheduled jobs
                for job in list(self.scheduled_jobs.values()):
                    if not job.enabled:
                        continue

                    if job.next_run and current_time >= job.next_run:
                        # Execute job
                        asyncio.create_task(self._execute_scheduled_job(job))

                        # Update next run time
                        self._update_next_run_time(job)

                # Sleep for 30 seconds before next check
                await asyncio.sleep(30)

            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    async def _execute_scheduled_job(self, job: ScheduledJob) -> Optional[WorkflowResult]:
        """Execute a scheduled job"""
        try:
            self.logger.info(f"Executing scheduled job: {job.name}")

            # Update job statistics
            job.last_run = datetime.now()
            job.run_count += 1

            # Create workflow and execute
            workflow = AutomatedWorkflow(job.config)
            result = await workflow.execute_workflow()

            # Update job result and statistics
            job.last_result = result
            if result.success:
                job.success_count += 1
            else:
                job.failure_count += 1

            # Save updated job data
            self._save_jobs()

            self.logger.info(
                f"Scheduled job completed: {job.name} "
                f"({'SUCCESS' if result.success else 'FAILED'})"
            )

            return result

        except Exception as e:
            self.logger.error(f"Error executing scheduled job {job.name}: {e}")
            job.failure_count += 1
            self._save_jobs()
            return None

    async def _execute_batch_job(self, job: BatchJob) -> List[WorkflowResult]:
        """Execute a batch processing job"""
        try:
            self.logger.info(f"Executing batch job: {job.name} ({len(job.pcap_pairs)} pairs)")

            results = []

            if job.parallel_execution:
                # Execute in parallel with concurrency limit
                semaphore = asyncio.Semaphore(job.max_concurrent)

                async def execute_pair(recon_pcap: str, zapret_pcap: str) -> WorkflowResult:
                    async with semaphore:
                        # Create config for this pair
                        config = WorkflowConfig(
                            recon_pcap_path=recon_pcap,
                            zapret_pcap_path=zapret_pcap,
                            target_domains=job.base_config.target_domains,
                            output_dir=f"{job.base_config.output_dir}/batch_{job.id}",
                            enable_auto_fix=job.base_config.enable_auto_fix,
                            enable_validation=job.base_config.enable_validation,
                            max_fix_attempts=job.base_config.max_fix_attempts,
                            validation_timeout=job.base_config.validation_timeout,
                            parallel_validation=job.base_config.parallel_validation,
                            backup_before_fix=job.base_config.backup_before_fix,
                            rollback_on_failure=job.base_config.rollback_on_failure,
                        )

                        workflow = AutomatedWorkflow(config)
                        return await workflow.execute_workflow()

                # Execute all pairs
                tasks = [
                    execute_pair(recon_pcap, zapret_pcap)
                    for recon_pcap, zapret_pcap in job.pcap_pairs
                ]

                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Handle exceptions
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        self.logger.error(f"Batch job pair {i} failed: {result}")
                        # Create a failed result
                        results[i] = WorkflowResult(
                            success=False, execution_time=0, error_details=str(result)
                        )

            else:
                # Execute sequentially
                for recon_pcap, zapret_pcap in job.pcap_pairs:
                    config = WorkflowConfig(
                        recon_pcap_path=recon_pcap,
                        zapret_pcap_path=zapret_pcap,
                        target_domains=job.base_config.target_domains,
                        output_dir=f"{job.base_config.output_dir}/batch_{job.id}",
                        enable_auto_fix=job.base_config.enable_auto_fix,
                        enable_validation=job.base_config.enable_validation,
                        max_fix_attempts=job.base_config.max_fix_attempts,
                        validation_timeout=job.base_config.validation_timeout,
                        parallel_validation=job.base_config.parallel_validation,
                        backup_before_fix=job.base_config.backup_before_fix,
                        rollback_on_failure=job.base_config.rollback_on_failure,
                    )

                    workflow = AutomatedWorkflow(config)
                    result = await workflow.execute_workflow()
                    results.append(result)

            # Update batch job results
            job.results = results
            self._save_jobs()

            success_count = sum(1 for r in results if r.success)
            self.logger.info(
                f"Batch job completed: {job.name} " f"({success_count}/{len(results)} successful)"
            )

            return results

        except Exception as e:
            self.logger.error(f"Error executing batch job {job.name}: {e}")
            return []

    def _update_next_run_time(self, job: ScheduledJob) -> None:
        """Update the next run time for a scheduled job"""
        if job.schedule_type == "interval":
            minutes = job.schedule_params.get("minutes", 60)
            job.next_run = datetime.now() + timedelta(minutes=minutes)

        elif job.schedule_type == "daily":
            hour = job.schedule_params.get("hour", 2)
            minute = job.schedule_params.get("minute", 0)

            next_run = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= datetime.now():
                next_run += timedelta(days=1)
            job.next_run = next_run

        elif job.schedule_type == "weekly":
            weekday = job.schedule_params.get("weekday", 0)
            hour = job.schedule_params.get("hour", 2)
            minute = job.schedule_params.get("minute", 0)

            now = datetime.now()
            days_ahead = weekday - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7

            next_run = now + timedelta(days=days_ahead)
            next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
            job.next_run = next_run

    def _save_jobs(self) -> None:
        """Save jobs to persistent storage"""
        try:
            jobs_data = {"scheduled_jobs": {}, "batch_jobs": {}}

            # Save scheduled jobs
            for job_id, job in self.scheduled_jobs.items():
                job_data = {
                    "id": job.id,
                    "name": job.name,
                    "config": job.config.__dict__,
                    "schedule_type": job.schedule_type,
                    "schedule_params": job.schedule_params,
                    "enabled": job.enabled,
                    "last_run": job.last_run.isoformat() if job.last_run else None,
                    "next_run": job.next_run.isoformat() if job.next_run else None,
                    "run_count": job.run_count,
                    "success_count": job.success_count,
                    "failure_count": job.failure_count,
                }
                jobs_data["scheduled_jobs"][job_id] = job_data

            # Save batch jobs
            for job_id, job in self.batch_jobs.items():
                job_data = {
                    "id": job.id,
                    "name": job.name,
                    "pcap_pairs": job.pcap_pairs,
                    "base_config": job.base_config.__dict__,
                    "parallel_execution": job.parallel_execution,
                    "max_concurrent": job.max_concurrent,
                }
                jobs_data["batch_jobs"][job_id] = job_data

            # Write to file
            jobs_file = self.scheduler_dir / "jobs.json"
            with open(jobs_file, "w", encoding="utf-8") as f:
                json.dump(jobs_data, f, indent=2, default=str)

        except Exception as e:
            self.logger.error(f"Failed to save jobs: {e}")

    def _load_jobs(self) -> None:
        """Load jobs from persistent storage"""
        try:
            jobs_file = self.scheduler_dir / "jobs.json"
            if not jobs_file.exists():
                return

            with open(jobs_file, "r", encoding="utf-8") as f:
                jobs_data = json.load(f)

            # Load scheduled jobs
            for job_id, job_data in jobs_data.get("scheduled_jobs", {}).items():
                config = WorkflowConfig(**job_data["config"])

                job = ScheduledJob(
                    id=job_data["id"],
                    name=job_data["name"],
                    config=config,
                    schedule_type=job_data["schedule_type"],
                    schedule_params=job_data["schedule_params"],
                    enabled=job_data["enabled"],
                    run_count=job_data.get("run_count", 0),
                    success_count=job_data.get("success_count", 0),
                    failure_count=job_data.get("failure_count", 0),
                )

                # Parse datetime fields
                if job_data.get("last_run"):
                    job.last_run = datetime.fromisoformat(job_data["last_run"])
                if job_data.get("next_run"):
                    job.next_run = datetime.fromisoformat(job_data["next_run"])

                self.scheduled_jobs[job_id] = job

            # Load batch jobs
            for job_id, job_data in jobs_data.get("batch_jobs", {}).items():
                base_config = WorkflowConfig(**job_data["base_config"])

                job = BatchJob(
                    id=job_data["id"],
                    name=job_data["name"],
                    pcap_pairs=job_data["pcap_pairs"],
                    base_config=base_config,
                    parallel_execution=job_data.get("parallel_execution", True),
                    max_concurrent=job_data.get("max_concurrent", 3),
                )

                self.batch_jobs[job_id] = job

        except Exception as e:
            self.logger.error(f"Failed to load jobs: {e}")

    def get_job_status(self) -> Dict[str, Any]:
        """Get status of all jobs"""
        status = {
            "scheduler_running": self.running,
            "scheduled_jobs": len(self.scheduled_jobs),
            "batch_jobs": len(self.batch_jobs),
            "enabled_jobs": sum(1 for job in self.scheduled_jobs.values() if job.enabled),
            "jobs": [],
        }

        for job in self.scheduled_jobs.values():
            job_status = {
                "id": job.id,
                "name": job.name,
                "type": "scheduled",
                "schedule_type": job.schedule_type,
                "enabled": job.enabled,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "next_run": job.next_run.isoformat() if job.next_run else None,
                "run_count": job.run_count,
                "success_count": job.success_count,
                "failure_count": job.failure_count,
                "success_rate": job.success_count / max(job.run_count, 1),
            }
            status["jobs"].append(job_status)

        for job in self.batch_jobs.values():
            job_status = {
                "id": job.id,
                "name": job.name,
                "type": "batch",
                "pcap_pairs": len(job.pcap_pairs),
                "parallel_execution": job.parallel_execution,
                "max_concurrent": job.max_concurrent,
                "results_count": len(job.results),
            }
            status["jobs"].append(job_status)

        return status


if __name__ == "__main__":
    # Example usage
    async def main():
        setup_logging()
        scheduler = WorkflowScheduler()

        # Create a sample configuration
        config = WorkflowConfig(
            recon_pcap_path="recon_x.pcap",
            zapret_pcap_path="zapret_x.pcap",
            target_domains=["x.com"],
            output_dir="scheduled_results",
        )

        # Create and add a daily job
        daily_job = scheduler.create_daily_job("Daily X.com Analysis", config, hour=2)
        scheduler.add_scheduled_job(daily_job)

        # Create and add an interval job
        interval_job = scheduler.create_interval_job("Hourly Check", config, 60)
        scheduler.add_scheduled_job(interval_job)

        # Print job status
        status = scheduler.get_job_status()
        print(json.dumps(status, indent=2))

        # Start scheduler (would run indefinitely in real usage)
        await scheduler.start_scheduler()

        # In real usage, you would keep the scheduler running
        # await asyncio.sleep(3600)  # Run for 1 hour

        await scheduler.stop_scheduler()

    asyncio.run(main())
