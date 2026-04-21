from fastapi.responses import StreamingResponse
from datetime import datetime

from app.services.events.download_events_service import (
    generate_events_excel_report,
    generate_evidence_csv_report,
    generate_evidence_pdf_report,
)
from app.services.system.kernel_proof_service import compute_kernel_proof


def download_events_controller(action_filter: str = None, fmt: str = "xlsx"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = f"{action_filter.lower()}_{timestamp}" if action_filter and action_filter.lower() != "all" else f"all_{timestamp}"

    if fmt == "csv":
        kernel = compute_kernel_proof()
        data = generate_evidence_csv_report(action_filter, kernel)
        return StreamingResponse(
            data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=evidence_{suffix}.csv"},
        )

    if fmt == "pdf":
        kernel = compute_kernel_proof()
        data = generate_evidence_pdf_report(action_filter, kernel)
        return StreamingResponse(
            data,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=evidence_{suffix}.pdf"},
        )

    # Default: xlsx
    data = generate_events_excel_report(action_filter)
    return StreamingResponse(
        data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=events_{suffix}.xlsx"},
    )
