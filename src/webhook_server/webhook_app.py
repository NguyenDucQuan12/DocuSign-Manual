import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, HTTPException  # pip install "fastapi[standard]"
from fastapi.responses import PlainTextResponse

# =========================
# 1) Logging: log rõ để debug
# =========================
logger = logging.getLogger("docusign_webhook")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)

# =========================
# 2) ENV config
# =========================

# HMAC secret (Connect Key) nếu bạn bật includeHMAC=true trong Connect config
# Nếu bạn không dùng HMAC, có thể để trống => server sẽ skip verify
DOCUSIGN_HMAC_SECRET = os.getenv("DOCUSIGN_CONNECT_HMAC_SECRET", "").strip()

# Thư mục lưu file đã ký (ví dụ)
SIGNED_DIR = os.getenv("SIGNED_DIR", "./signed")
os.makedirs(SIGNED_DIR, exist_ok=True)

# Giới hạn kích thước payload để tránh bị spam/memory blow
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "5000000"))  # 5MB mặc định

# Queue nội bộ để tách “ACK nhanh” và “xử lý nặng”
JOB_QUEUE_MAXSIZE = int(os.getenv("JOB_QUEUE_MAXSIZE", "1000"))

# Số lần retry khi job nặng thất bại (tải pdf/network)
JOB_MAX_RETRIES = int(os.getenv("JOB_MAX_RETRIES", "5"))

# Backoff cơ bản (giây)
JOB_RETRY_BACKOFF_SEC = float(os.getenv("JOB_RETRY_BACKOFF_SEC", "3.0"))

# =========================
# 3) Idempotency: chống xử lý trùng
#    (Connect có thể retry nếu không ACK kịp)
# =========================

# TTL cache đơn giản: lưu "key -> expire_epoch"
# Dùng dict + lock để thread-safe
_DEDUPE: Dict[str, float] = {}
_DEDUPE_LOCK = threading.Lock()
DEDUPE_TTL_SEC = int(os.getenv("DEDUPE_TTL_SEC", "3600"))  # 1 giờ


def dedupe_seen(key: str) -> bool:
    """
    Trả True nếu key đã được xử lý gần đây.
    Nếu chưa thấy thì lưu vào cache và trả False.
    """
    now = time.time()
    with _DEDUPE_LOCK:
        # Dọn các key hết hạn để cache không phình
        expired = [k for k, exp in _DEDUPE.items() if exp < now]
        for k in expired:
            _DEDUPE.pop(k, None)

        # Nếu key đã tồn tại => coi như trùng
        if key in _DEDUPE:
            return True

        # Chưa có => lưu với TTL
        _DEDUPE[key] = now + DEDUPE_TTL_SEC
        return False


# =========================
# 4) Job model + worker thread
# =========================

@dataclass
class WebhookJob:
    """
    Job đại diện cho 1 webhook event cần xử lý nặng.
    """
    event_type: str
    envelope_id: str
    raw_body_sha256: str
    received_at_utc: str
    retry_count: int = 0


job_queue: "queue.Queue[WebhookJob]" = queue.Queue(maxsize=JOB_QUEUE_MAXSIZE)

_worker_stop = threading.Event()  # signal dừng worker khi shutdown


def safe_write_bytes(path: str, data: bytes) -> None:
    """
    Ghi file an toàn:
    - ghi ra file tạm
    - fsync
    - rename atomic
    """
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def download_signed_pdf(envelope_id: str) -> bytes:
    """
    Đây là tác vụ nặng ví dụ: download PDF đã ký.
    Bạn thay bằng DocuSignRestService của bạn (download combined).
    - Gợi ý: gọi API /documents/combined
    - Có thể include certificate nếu bạn muốn
    """
    # TODO: Thay bằng code thật của bạn.
    # Ví dụ (giả định bạn có service docusign):
    # pdf_bytes = docusign.download_completed_combined_pdf(envelope_id, include_certificate=True)
    # return pdf_bytes
    raise NotImplementedError("Implement download_signed_pdf(envelope_id) using your DocuSign REST client.")


def handle_job(job: WebhookJob) -> None:
    """
    Xử lý nặng cho 1 job:
    - ví dụ: tải PDF đã ký và lưu xuống disk
    - có thể: update DB, gọi internal APIs, gửi email thông báo...
    """
    logger.info(f"Worker handling job: event={job.event_type}, envelope={job.envelope_id}, retry={job.retry_count}")

    # Chỉ xử lý khi completed (có thể mở rộng thêm event khác)
    if job.event_type != "envelope-completed":
        logger.info(f"Skip heavy work for event={job.event_type}, envelope={job.envelope_id}")
        return

    # 1) Download PDF đã ký (tác vụ nặng/network)
    pdf_bytes = download_signed_pdf(job.envelope_id)

    # 2) Lưu file (đặt tên theo envelope_id)
    out_path = os.path.join(SIGNED_DIR, f"{job.envelope_id}.pdf")
    safe_write_bytes(out_path, pdf_bytes)

    logger.info(f"Saved signed PDF: {out_path}")


def worker_loop() -> None:
    """
    Worker thread:
    - lấy job từ queue
    - xử lý
    - nếu lỗi => retry với backoff (giới hạn số lần)
    """
    logger.info("Worker thread started.")
    while not _worker_stop.is_set():
        try:
            # Chờ lấy job; timeout để check stop signal định kỳ
            job = job_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        try:
            handle_job(job)  # chạy xử lý nặng
        except Exception as ex:
            # Lỗi xử lý nặng: log rõ
            logger.exception(f"Job failed: envelope={job.envelope_id}, event={job.event_type}, err={ex}")

            # Retry nếu chưa vượt giới hạn
            if job.retry_count < JOB_MAX_RETRIES:
                job.retry_count += 1

                # Backoff tăng dần tuyến tính (có thể đổi thành exponential)
                sleep_sec = JOB_RETRY_BACKOFF_SEC * job.retry_count
                logger.warning(
                    f"Retry job later: envelope={job.envelope_id}, retry={job.retry_count}, sleep={sleep_sec}s"
                )
                time.sleep(sleep_sec)

                # Đưa lại vào queue (nếu queue đầy sẽ drop và log)
                try:
                    job_queue.put_nowait(job)
                except queue.Full:
                    logger.error("Job queue full while retrying; dropping job to avoid deadlock.")
            else:
                logger.error(f"Job exceeded max retries; giving up: envelope={job.envelope_id}")

        finally:
            job_queue.task_done()

    logger.info("Worker thread stopped.")


# =========================
# 5) HMAC verification
# =========================

def compute_hmac_b64(secret: str, raw_body: bytes) -> str:
    """
    Tính HMAC-SHA256 rồi base64 encode.
    """
    mac = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("utf-8")


def verify_hmac_if_enabled(raw_body: bytes, headers: Dict[str, str]) -> None:
    """
    Nếu có DOCUSIGN_HMAC_SECRET:
    - lấy signature header
    - verify constant-time
    Nếu không bật secret => skip verify (không khuyến nghị production)
    """
    if not DOCUSIGN_HMAC_SECRET:
        return  # skip verify

    # DocuSign có thể dùng các tên header khác nhau tùy config/version.
    # Bạn nên log headers thực tế 1 lần để chốt đúng tên.
    signature = (
        headers.get("x-docusign-signature-1")
        or headers.get("x-docusign-signature")
        or headers.get("x-docsign-signature-1")
        or headers.get("x-docuSign-signature-1")
    )

    if not signature:
        raise HTTPException(status_code=401, detail="Missing DocuSign signature header")

    expected = compute_hmac_b64(DOCUSIGN_HMAC_SECRET, raw_body)

    # compare_digest để chống timing attack
    if not hmac.compare_digest(expected, signature.strip()):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")


# =========================
# 6) Parse payload: JSON SIM (khuyến nghị) + fallback XML
# =========================

def sha256_hex(data: bytes) -> str:
    """
    Hash body để:
    - tạo dedupe key
    - audit/debug
    """
    return hashlib.sha256(data).hexdigest()


def parse_json_sim(raw_body: bytes) -> Optional[Tuple[str, str]]:
    """
    Parse JSON SIM:
    - Trả (event_type, envelope_id) nếu tìm được
    - Nếu không match => None
    """
    payload = json.loads(raw_body.decode("utf-8"))

    # event type có thể nằm ở "event" hoặc "eventType"
    event_type = payload.get("event") or payload.get("eventType")

    # envelope id có thể nằm ở "envelopeId" hoặc payload["data"]["envelopeId"]
    envelope_id = payload.get("envelopeId")
    if not envelope_id:
        data = payload.get("data") or {}
        envelope_id = data.get("envelopeId")

    if not event_type or not envelope_id:
        return None

    return event_type, envelope_id


def parse_xml_minimal(raw_body: bytes) -> Optional[Tuple[str, str]]:
    """
    Fallback XML parse (tối thiểu):
    - Một số cấu hình Connect legacy có thể gửi XML.
    - Ở đây parse đơn giản để lấy envelopeId + status/event nếu có.
    """
    import xml.etree.ElementTree as ET

    root = ET.fromstring(raw_body)

    # Try tìm envelopeId theo các tag thường gặp
    # (Bạn có thể phải chỉnh theo payload thực tế nếu bạn dùng XML)
    envelope_id = None
    for tag in ["EnvelopeID", "EnvelopeId", "envelopeId"]:
        node = root.find(f".//{tag}")
        if node is not None and node.text:
            envelope_id = node.text.strip()
            break

    # Try tìm status/event
    event_type = None
    for tag in ["Status", "status", "Event", "event"]:
        node = root.find(f".//{tag}")
        if node is not None and node.text:
            event_type = node.text.strip()
            break

    # Map status -> event_type chuẩn hóa (ví dụ)
    # Nếu status="Completed" => ta convert thành "envelope-completed"
    if event_type and event_type.lower() == "completed":
        event_type = "envelope-completed"

    if not envelope_id or not event_type:
        return None

    return event_type, envelope_id


# =========================
# 7) FastAPI app lifecycle
# =========================

app = FastAPI()


@app.on_event("startup")
def on_startup() -> None:
    """
    Startup:
    - khởi động worker thread để xử lý nặng độc lập
    """
    t = threading.Thread(target=worker_loop, daemon=True)
    t.start()
    logger.info("App startup completed.")


@app.on_event("shutdown")
def on_shutdown() -> None:
    """
    Shutdown:
    - signal worker dừng
    """
    _worker_stop.set()
    logger.info("App shutdown signal set.")


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    """
    Health check endpoint:
    - giúp LB/k8s check service sống
    """
    return {
        "status": "ok",
        "queue_size": job_queue.qsize(),
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }


# =========================
# 8) Webhook endpoint
# =========================

@app.post("/webhooks/docusign")
async def docusign_webhook(request: Request):
    """
    Endpoint nhận webhook DocuSign Connect:
    - Verify HMAC (nếu bật)
    - Parse JSON SIM / fallback XML
    - Dedupe tránh xử lý trùng
    - Enqueue job nặng
    - ACK 200 nhanh
    """

    # 1) Đọc raw body
    raw_body = await request.body()

    # 2) Chặn payload quá lớn (bảo vệ server)
    if len(raw_body) > MAX_BODY_BYTES:
        # Trả 413 để báo payload quá lớn
        raise HTTPException(status_code=413, detail="Payload too large")

    # 3) Verify HMAC nếu cấu hình secret
    #    Nếu signature invalid => 401 (đúng bảo mật, DocuSign có thể retry nhưng sẽ fail tiếp)
    verify_hmac_if_enabled(raw_body, {k.lower(): v for k, v in request.headers.items()})

    # 4) Tạo dedupe key để tránh xử lý trùng
    #    (Connect có retry nếu không nhận ACK kịp)
    body_hash = sha256_hex(raw_body)
    dedupe_key = f"body:{body_hash}"

    # Nếu đã xử lý gần đây => ACK 200 ngay (idempotent)
    if dedupe_seen(dedupe_key):
        return PlainTextResponse("OK (duplicate ignored)", status_code=200)

    # 5) Parse payload theo Content-Type
    content_type = (request.headers.get("content-type") or "").lower()

    event_type = None
    envelope_id = None

    try:
        # JSON SIM: application/json hoặc body bắt đầu bằng '{'
        if "application/json" in content_type or raw_body.strip().startswith(b"{"):
            parsed = parse_json_sim(raw_body)
            if parsed:
                event_type, envelope_id = parsed

        # XML legacy fallback: application/xml hoặc body bắt đầu bằng '<'
        elif "application/xml" in content_type or raw_body.strip().startswith(b"<"):
            parsed = parse_xml_minimal(raw_body)
            if parsed:
                event_type, envelope_id = parsed

    except Exception as ex:
        # Parse lỗi: để tránh DocuSign retry vô hạn (vì payload sai) ta ACK 200 nhưng log lại
        logger.warning(f"Webhook parse error (ACK 200 to stop retry). err={ex}")
        return PlainTextResponse("OK (parse error ignored)", status_code=200)

    # Nếu không parse được event/envelopeId => ACK 200 để tránh retry vô ích
    if not event_type or not envelope_id:
        logger.info("Webhook received but no actionable event/envelopeId found.")
        return PlainTextResponse("OK (no actionable event)", status_code=200)

    # 6) Enqueue job nặng để xử lý riêng, ACK nhanh
    job = WebhookJob(
        event_type=event_type,
        envelope_id=envelope_id,
        raw_body_sha256=body_hash,
        received_at_utc=datetime.now(timezone.utc).isoformat(),
    )

    try:
        # put_nowait để không block request handler
        job_queue.put_nowait(job)
    except queue.Full:
        # Queue đầy => trả 503 để DocuSign retry sau (tốt hơn drop job)
        logger.error("Job queue full. Returning 503 so DocuSign can retry.")
        raise HTTPException(status_code=503, detail="Server busy, queue full")

    # 7) ACK 200 ngay lập tức (đáp ứng requiresAcknowledgement)
    return PlainTextResponse("OK", status_code=200)
