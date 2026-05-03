import asyncio

from app.core.config import settings
from app.core.logger import logger
from app.graph.workflow import process_finding
from app.schemas.patch_schema import AIBatchResult
from app.schemas.sarif_schema import ScanResultMessage


async def process_scan_message(scan_msg: ScanResultMessage) -> AIBatchResult:
    scan_id = scan_msg.scan_id
    project_id = scan_msg.project_id
    findings = list(scan_msg.findings)

    if not findings:
        return AIBatchResult(
            scan_id=scan_id,
            project_id=project_id,
            results=[],
            total_findings=0,
            total_processed=0,
            total_patches_generated=0,
            total_patches_approved=0,
        )

    semaphore = asyncio.Semaphore(settings.BROKER_MAX_CONCURRENCY)

    async def run_one(finding) -> object:
        async with semaphore:
            finding_dict = finding.model_dump(by_alias=True)
            return await process_finding(finding_dict, scan_id, project_id)

    tasks = [asyncio.create_task(run_one(f)) for f in findings]
    results = await asyncio.gather(*tasks)

    total_patches_generated = sum(1 for r in results if getattr(r, "patch", None))
    total_patches_approved = sum(
        1 for r in results if getattr(r, "review", None) and r.review.approved
    )

    batch = AIBatchResult(
        scan_id=scan_id,
        project_id=project_id,
        results=results,
        total_findings=len(findings),
        total_processed=len(results),
        total_patches_generated=total_patches_generated,
        total_patches_approved=total_patches_approved,
    )

    logger.info("scan_batch_completed", scan_id=scan_id, summary=batch.summary_str())
    return batch
