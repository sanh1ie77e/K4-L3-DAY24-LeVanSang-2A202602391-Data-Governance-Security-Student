"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _authorize(context: PolicyContext, arguments: dict, path: Path,
               run_id: str, operation: str = "tool-call") -> bool:
    allow, reason = policy.check(context)
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Policy decision must have a non-empty reason")
    args_hash = hashlib.sha256(
        json.dumps(arguments, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": context.agent_owner,
        "run_id": run_id,
        "on_behalf_of": context.principal_id,
        "expires_at": context.expires_at,
        "tool": context.requested_tool,
        "args_hash": args_hash,
        "classification": context.data_classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
        "operation": operation,
    }, path)
    return allow


def _run_b(ticket_ids: tuple[int, ...], context: PolicyContext,
           ledger_path: Path, run_id: str) -> int:
    # Kiểm quyền TRƯỚC cả việc mở store để tìm related_tickets.
    if not _authorize(context, {"ticket_ids": ticket_ids}, ledger_path,
                      run_id, operation="resolve-related-tickets"):
        return 0
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    customer_ids = dict.fromkeys(
        row["customer_id"] for row in customers
        if wanted.intersection(row.get("related_tickets", []))
    )
    read_count = 0
    for customer_id in customer_ids:
        if _authorize(context, {"customer_id": customer_id}, ledger_path, run_id):
            tools.read_customer(customer_id)
            read_count += 1
    return read_count


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH
    agent_id = f"lab24-agent-{uuid4().hex}"
    run_a, run_b = uuid4().hex, uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    # Hai run là con của coordinator, không phải Run B kế thừa quyền từ Run A.
    coordinator_scopes = ("search_docs", "read_customer", "http_post")
    context_a = PolicyContext(
        data_classification="internal", request_purpose="summarize-tickets",
        agent_owner=agent_id, delegation_depth=1, egress_enabled=False,
        principal_id=principal_id, requested_tool="search_docs",
        agent_scopes=("search_docs",), parent_scopes=coordinator_scopes,
        expires_at=expires_at,
    )
    if not _authorize(context_a, {"query": message}, path, run_a):
        return "Yêu cầu tìm ticket bị từ chối; xem reason trong ledger."

    docs = tools.search_docs(message)
    safe_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    injected = llm.find_injection("\n\n".join(doc["text"] for doc in safe_docs))
    if injected is not None:
        # Yêu cầu egress từ tài liệu được đánh giá và ghi deny ngay trong Run A.
        # URL/ID từ free text không được dùng để chọn khách hoặc truyền sang B.
        egress_context = replace(context_a, data_classification="restricted",
                                 requested_tool="http_post", egress_enabled=True)
        if _authorize(egress_context,
                      {"url": injected.target_url},
                      path, run_a, operation="untrusted-egress-request"):
            raise RuntimeError("Run A does not support egress")

    ticket_ids = set()
    for doc in docs:
        match = re.fullmatch(r"ticket-([0-9]+)(?:b)?\.md", doc["id"])
        if match:
            ticket_ids.add(int(match.group(1)))
    context_b = replace(context_a, data_classification="restricted",
                        request_purpose="support-reply", requested_tool="read_customer",
                        agent_scopes=("read_customer",))
    read_count = _run_b(tuple(sorted(ticket_ids)), context_b, path, run_b)
    answer = pii.redact(llm.summarize(safe_docs))
    if read_count:
        answer += f" Đã xử lý {read_count} hồ sơ liên quan theo quyền được cấp."
    return answer
