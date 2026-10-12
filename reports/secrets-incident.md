# Secret giả trong lịch sử Git — điền trong checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1` (`gitleaks version`), bản release chính thức `gitleaks_8.30.1_darwin_arm64.tar.gz`, SHA-256 `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`, đã khớp với `gitleaks_8.30.1_checksums.txt`. Cấu hình dùng `.gitleaks.toml` (default rules + rule `lab24-synthetic-token`).
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`, "chore: seed student lab with synthetic secret exercise", 2026-10-09). File bị xoá ở commit kế tiếp `ece6ca4`.
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` → `4 commits scanned`, `leaks found: 1`, exit code `1` (đúng như đề dự kiến).
  - RuleID: `lab24-synthetic-token`; File: `lab-fake-secret.txt`, Line 1; Commit `1bdd849`; Entropy 4.60.
  - Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`.
  - Giá trị đã được `--redact`. Đây là token **giả, vô hiệu** do đề cài sẵn (dạng `LAB24_FAKE_TOKEN=LAB24-DEMO-…`), **không phải** sự cố bảo mật thật.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit `0`. Hook `pre-commit run --all-files` (`gitleaks-system`, pin `v8.30.1`) → `Passed`.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi / rotate ngay** credential ở hệ thống phát hành (revoke token, cấp token mới, cập nhật nơi dùng qua secret manager). Đây là bước bắt buộc và phải làm trước tiên.
  2. Tra log truy cập của dịch vụ từ thời điểm commit `1bdd849` (2026-10-09) đến lúc thu hồi để tìm việc dùng trái phép, rồi đánh giá phạm vi ảnh hưởng.
  3. Sau khi đã rotate, mới cân nhắc viết lại lịch sử (`git filter-repo`) và force-push, đồng thời báo mọi người có clone/fork. Việc này chỉ giảm phơi nhiễm về sau, không thay thế bước 1.
  4. Ghi incident: ai phát hiện, khi nào, thời gian phơi nhiễm, hành động đã làm. Thêm hook để chặn tái diễn.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Xoá file ở `ece6ca4` không xoá blob trong lịch sử: ai có clone hoặc fork vẫn lấy lại được bằng `git show 1bdd849:lab-fake-secret.txt`. Mirror, cache và CI log cũng có thể đã sao chép nó. Credential vẫn **còn hiệu lực** cho tới khi bị thu hồi ở phía phát hành.
  - Pin dependency (`requirements.lock` có `--hash=sha256`, cài bằng `--require-hashes`) và hook pin `v8.30.1` là control **phòng ngừa**: chặn package bị tráo và chặn commit secret **mới**. Chúng không có tác dụng ngược thời gian với một secret đã lộ. Chỉ **rotate/thu hồi** mới làm secret đã lộ mất giá trị.
