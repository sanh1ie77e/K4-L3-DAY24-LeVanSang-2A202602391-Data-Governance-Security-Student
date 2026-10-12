# Baseline — Checkpoint 1

1. **Mỗi lần chạy baseline đã có agent_id/run_id và danh tính người dùng để kiểm quyền chưa?**

   hiện tại `_naive_loop()` nó chỉ nhận `message` và `llm`, chưa tạo `agent_id` hay là `run_id` để phân biệt từng lần chạy (`agent/loop.py:27`). Mặc dù hàm `run_once()` có nhận `principal_id` (`agent/loop.py:58`), nhưng nó không được truyền qua fallback mà gọi `_naive_loop(message, llm)` (`agent/loop.py:74`), vậy nên baseline chưa có danh tính người dùng mà phải kiểm quyền trước khi đọc hoặc là gửi dữ liệu.

2. **Trước http_post, có policy kiểm mục đích, quyền và loại dữ liệu không? Ai thực sự quyết định gửi?**

   Trong `_naive_loop()`,không thấy có bước kiểm policy về mục đích, về quyền hay loại dữ liệu trước lời gọi `read_customer()` (`agent/loop.py:39`) và `http_post()` (`agent/loop.py:44`). Baseline lấy nội dung từ ticket qua `find_injection()` (`agent/loop.py:34`), đọc các ID trong chỉ thị rồi gửi tới `injected.target_url` khi có record (`agent/loop.py:37`, `agent/loop.py:42`, `agent/loop.py:44`), tức ticket là dữ liệu nhưng chỉ thị bên trong lại được xử lý như lệnh. Hàm `http_post()` chỉ giới hạn scheme, host và port của URL về localhost (`agent/tools.py:76`, `agent/tools.py:77`, `agent/tools.py:78`), không kiểm tra hồ sơ nào được phép gửi.

3. **Dòng nào tạo body POST, và file nào ghi lại việc sink đã nhận body đó?**

   Body `{"records": collected}` được tạo tại `agent/loop.py:44` và gửi dưới dạng JSON bằng `requests.post(url, json=body, timeout=timeout)` tại `agent/tools.py:84`. Khi sink nhận POST, hàm `Handler.do_POST()` tạo entry gồm `path` và `body`, rồi ghi entry vào log (`sink/sink.py:45`, `sink/sink.py:47`); đường dẫn log mặc định là `reports/sink.log` (`sink/sink.py:37`). Ở CP2, cần kiểm tra body trong log thực nhận có hồ sơ giả `KH-000999` và các trường CCCD/STK, rồi sao chép log thành `reports/attack-before.log` để giữ bằng chứng trước khi sửa agent.
