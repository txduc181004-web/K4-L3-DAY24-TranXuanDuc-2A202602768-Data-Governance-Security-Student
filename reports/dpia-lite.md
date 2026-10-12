# DPIA-lite — điền trong checkpoint 5

> Đánh giá trên hệ thống **mô phỏng**: dữ liệu synthetic, LLM `--mock`, sink localhost. Không phải DPIA cho một hệ thống production.

1. **Loại dữ liệu và phân loại:**
   - `data/customers.json` (26 hồ sơ synthetic): họ tên, **CCCD**, **SĐT**, **số tài khoản ngân hàng**, email, `related_tickets`. Phân loại nội bộ **restricted**, vì CCCD và STK cho phép định danh và gây thiệt hại tài chính. Theo pháp luật (đối chiếu bản đăng lại trên LuatVietnam, xem `reports/compliance-mapping.md`):
     - Số CCCD (số định danh cá nhân) và SĐT là dữ liệu **cơ bản** (NĐ 356/2025/NĐ-CP, Điều 3 khoản 7).
     - Thông tin tài khoản ngân hàng/tài chính là dữ liệu **nhạy cảm** (Điều 4 khoản 1 điểm k).
     - Nhãn `restricted` cố ý chặt hơn mức luật yêu cầu.
   - `corpus/ticket-*.md` (40 ticket + 5 file lure 901–904b): nội dung hỗ trợ khách hàng, **có lẫn** STK/SĐT/CCCD/email trong văn bản tự do. Phân loại **internal**, đồng thời là **untrusted content** vì bên ngoài viết được vào (đường vào của prompt injection).
   - `data/principals.json`: quyền của vai trò, là nguồn tin cậy mô phỏng.
   - `reports/ledger.jsonl`: metadata tool call, **không** chứa PII thô (chỉ `args_hash` SHA-256, customer id nằm trong hash).
2. **Mục đích xử lý và principal:**
   - `support_l1`: `summarize-tickets`, `support-reply`; chỉ được `search_docs`. Không được đọc hồ sơ khách.
   - `dpo`: `summarize-tickets`, `support-reply`, `privacy-audit`; được `search_docs` và `read_customer`.
   - `billing`: có trong fixture nhưng không dùng trong bài.
   - Quy tắc: đọc dữ liệu `restricted` chỉ với purpose `support-reply` / `billing-reconciliation` / `privacy-audit`. Run B dùng `support-reply`. Không principal nào có `http_post`.
3. **Dữ liệu đi qua những run/tool nào, endpoint nào:**
   - **Run A** (`lab24-agent/run-a`, scope `search_docs`): `search_docs` đọc corpus → `pii.redact()` → LLM (`find_injection`, `summarize`). Các tool call do injection đề xuất (`read_customer`, `http_post`) bị deny ở PEP.
   - **Boundary A→B:** chỉ `list[int]` ticket id lấy từ tên file. Không có free text và PII nào đi qua.
   - **Run B** (`lab24-agent/run-b`, scope `read_customer`): ticket id → `related_tickets` → `read_customer`. Kết quả chỉ trả `customer_id` ra màn hình, không in CCCD/STK.
   - **Egress:** endpoint duy nhất có thể tới là `http://127.0.0.1:10024/*` (sink cục bộ, allowlist cứng ở `agent/tools.py:76-83`). Sau containment **không** có request nào tới sink: `reports/attack-after.log` = 0 byte.
   - Cả hai run được ủy quyền từ orchestrator (`delegation_depth=1`, `parent_scopes=("search_docs","read_customer")`) với TTL 5 phút.
4. **Bằng chứng deny/allow và giới hạn của mock:**
   - Trước khi contain: `reports/attack-before.log` chứa record synthetic của `KH-000999` (CCCD `811753472374`, SĐT, STK, email).
   - Sau khi contain (`--as support_l1` rồi `--as dpo`, cùng query): `reports/ledger.jsonl` có 48 dòng, `verify() == True`.
     - Dòng 2–3 (`support_l1`, run-a): deny `read_customer` và deny `http_post` với reason `restricted+egress`.
     - Dòng 4–24 (`support_l1`, run-b): deny `read_customer` (principal không được cấp tool).
     - Dòng 26–27 (`dpo`, run-a): deny `read_customer` ngoài scope run-a; deny `http_post` với reason `restricted+egress`.
     - Dòng 28–48 (`dpo`, run-b): allow `read_customer` cho 21 khách gắn với ticket hợp lệ (gồm `KH-000999` qua ticket 901–905).
   - Test: `python -m pytest tests/ -q` → 33 passed (xem `reports/verification.md`).
   - **Giới hạn:**
     - Mock LLM phát hiện chỉ thị bằng marker. Model thật có thể bị điều khiển theo cách khác, nhưng containment kiến trúc (split + PEP) không phụ thuộc vào việc phát hiện.
     - `--as` là principal giả lập, không có xác thực.
     - Ticket hợp lệ đã gắn với hồ sơ nạn nhân nên `dpo` vẫn đọc hồ sơ đó. Lớp chặn cuối là PEP egress; nếu policy cấu hình sai thì không còn lớp nào khác.
     - Regex PII chỉ phủ 4 loại và đạt recall 1.000 trên test set synthetic, chưa đo trên dữ liệu thật.
     - Ledger không chống cắt đuôi/viết lại toàn bộ khi không có mốc tin cậy bên ngoài.
     - Chưa xét consent, quyền chủ thể dữ liệu, thời hạn lưu trữ và chuyển dữ liệu xuyên biên giới.
