# Ghi lại phần kiểm tra trước khi nộp

Mình làm trên Windows native, dùng Python 3.13.15, Gitleaks 8.30.1 và pre-commit 4.6.2. Sau CP4/CP5 ngày 12/10/2026, lệnh `python -m pytest tests/ -q --basetemp=.pytest_tmp` chạy được **46 passed, 0 failed, 0 skipped**. Pre-commit cũng Passed, hook đã cài vào `.git/hooks/pre-commit`.

Kết quả sau lần replay cuối là ledger có 99 dòng, verify=True, còn `attack-after.log` vẫn 0 byte. Baseline đã chạy riêng cho đủ bốn lure. Mình có làm thêm báo cáo supply chain, compliance mapping và DPIA-lite, nhưng phần điều/khoản pháp luật cụ thể thì chưa xác minh.

Ở dưới có vài chỗ ghi ledger 27, 51 hoặc 75 dòng. Đó là số mình ghi lại sau từng lần chạy, trước khi chạy bổ sung. Số cuối cùng là 99 dòng, có ghi ở cuối bài.

## Nhiệm vụ 2: CP3a, CP3b, CP3c

Đầu tiên mình chạy ba nhóm test PII, policy và OBO ở thư mục repo, bằng Python trong `.venv`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_pii.py tests/test_policy.py tests/test_obo.py -v -s --basetemp=.pytest_tmp
```

Chạy ra **11 passed**: PII có 2 test, policy 4 và OBO 5. Phần PII in ra:

```text
[pii] gold=118 pred=118 tp=118
[pii] precision=1.000 recall=1.000
```

Recall đạt 100% trên bộ mẫu này, qua mức >95% của rubric. Tuy nhiên cách chấm của đề là cùng loại và span có giao với nhãn thì tính đúng. Mình có kiểm tra thêm offset bằng `text[start:end]` trên ví dụ có STK, CCCD, điện thoại có định dạng và email, để xem phần cắt chuỗi có đúng hay không.

Regex vẫn còn vài chỗ chưa xử lý được. Nó chỉ nhìn dạng chuỗi, không biết số CCCD, điện thoại hay tài khoản đó có thật và của ai. Với STK, phải có nhãn `STK`, `số tài khoản`, `so tai khoan` hoặc `bank_account`. Nếu để mỗi dãy số thì có thể bỏ sót, hoặc nhận sang CCCD/điện thoại.

Số điện thoại mới nhận dạng bắt đầu bằng 0, tổng 10–11 chữ số, có thể có dấu cách hay gạch ngang. Dạng +84 chưa hỗ trợ đầy đủ. CCCD thì mới nhận 12 số liền nhau, chưa bao hết kiểu tách số, thay ký tự hay lỗi OCR. Email cũng chỉ dùng dạng ASCII thông dụng, chưa đủ mọi địa chỉ hợp lệ theo chuẩn quốc tế. Tên người, địa chỉ và thông tin nhạy cảm suy ra từ ngữ cảnh thì chưa nhận diện.

Vậy nên kết quả 1.000 ở trên mới nói được bộ test hiện tại chạy đúng, chưa đủ để đánh giá dữ liệu ngoài testset.

Sau đó mình chạy thêm các trường hợp biên cùng những test phụ thuộc:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_cp3_boundaries.py tests/test_split.py tests/test_ledger.py tests/test_scaffold_dispatch.py tests/test_injection.py -v --basetemp=.pytest_tmp
```

Lúc này được **23 passed, 6 skipped**. Sáu test skip thuộc injection 2, 3, 4 dưới hai principal, vì corpus chính khi đó chưa có các lure này. Sang Nhiệm vụ 3 mới thêm đủ và chạy lại hết, không còn skip.

Phần test bổ sung kiểm tra STK 12 số có bị nhận trùng thành CCCD không, offset/redaction, và các trường hợp purpose, scope, TTL không hợp lệ. Có kiểm cả unknown principal không được search, `support_l1` bị chặn ngay trước lúc mở private store. Text đưa vào mock LLM và ledger cũng được kiểm để không còn PII thô từ ticket thử nghiệm. Các test split, hash chain, sửa dòng ledger và dispatch fallback có sẵn đều pass. Test bắt buộc mình giữ nguyên.

Tiếp theo là chạy CLI cho hai principal:

```powershell
.\.venv\Scripts\python.exe -m agent.loop --mock --as support_l1 "Tổng hợp các ticket còn mở tuần này"
.\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
```

Cả hai đều tổng hợp 41 ticket. Mình đối chiếu `reports/ledger.jsonl` lúc đó được bảng này:

| Principal | search_docs allow | read_customer tool-call allow | read_customer deny | http_post deny |
|---|---:|---:|---:|---:|
| support_l1 | 1 | 0 | 1 | 1 |
| dpo | 1 | 21 | 0 | 1 |

Ledger có 27 entry, 2 `agent_id`, 4 `run_id`. Các entry đều có `on_behalf_of`, `expires_at` và reason. Ngoài 21 lần DPO gọi `read_customer`, còn một entry allow của `read_customer` với operation `resolve-related-tickets`. Đây là bước mở store và ánh xạ ticket, cũng kiểm quyền trước khi làm.

Gọi `agent.ledger.verify(Path('reports/ledger.jsonl'))` được `True`. Đối chiếu với dataset thì ledger không chứa CCCD/SĐT/STK thô. Hai entry `http_post` trong bảng là quyết định deny đối với yêu cầu egress từ tài liệu, không có POST thật được gửi ở hai lần đó.

Trước khi thay runner, mình đã giữ một dòng POST có sẵn ở `reports/sink.log` sang `reports/attack-before.log`. Body khớp hồ sơ synthetic trong `data/customers.json`, có KH-000999. Đây là log baseline có từ trước, không phải log tạo sau containment hoặc lấy từ folder mẫu `check`.

Phần quyền ở lab cũng có giới hạn. `--as` chỉ chọn principal mô phỏng trong fixture, chưa xác thực người dùng thật. Quyền tool lấy giao của principal, agent scopes và parent scopes nếu có delegation. Run A và Run B là hai run con của coordinator, có scope riêng, TTL mặc định 5 phút.

Ledger dùng hash chain nên sửa một dòng mà không tính lại hash sẽ bị phát hiện. Còn cắt đuôi hoặc viết lại cả chuỗi thì chưa phát hiện được nếu thiếu mốc tin cậy ngoài file. Append hiện chạy tuần tự cho lab, chưa có khóa ghi giữa nhiều tiến trình. Mình chưa xem phần này là audit bất biến hay hệ thống dùng được trong production.

## Nhiệm vụ 3: CP3d, CP3e và injection

Trong `agent/runner.py`, mình giữ split A/B. A dùng `search_docs`, che PII và lấy ID ticket từ tên file. B nhận tuple số, kiểm quyền trước khi mở store và trước mỗi `read_customer`, rồi ánh xạ bằng `related_tickets`. Customer ID nằm trong text không được dùng để chọn hồ sơ.

Ở bước kiểm `http_post`, classification là `restricted`, `egress_enabled=True`. Chỉ hash đối số URL, không kèm hồ sơ hay customer ID. Nếu deny thì không gọi `tools.http_post`.

Mình thêm `corpus/ticket-902.md`, `ticket-903.md`, `ticket-904.md` và `ticket-904b.md`, còn lure 901 giữ nguyên. Như vậy có đủ bốn biến thể để thử. `agent/ledger.py` đã có append/verify từ phần OBO, ở đây mình kiểm lại hash chain và thử sửa một dòng giữa bản sao ledger.

```powershell
.\.venv\Scripts\python.exe -m agent.check_lure 'corpus/ticket-90*.md'
.\.venv\Scripts\python.exe -m pytest tests/test_split.py tests/test_injection.py tests/test_ledger.py -v --basetemp=.pytest_tmp
```

Checker báo **4/4 lure sẵn sàng**. Với 904/904b, kiểm từng file riêng đều ra `find_injection=None`; ghép hai file lại thì nhận hai marker và KH-000999.

Nhóm split được **1 passed**. KH-000777 không bị đọc chỉ vì xuất hiện trong text, còn khách gắn với ticket hợp lệ vẫn đọc được dưới DPO. Injection được **8 passed, 0 skipped**, tức bốn lure chạy dưới cả `support_l1` lẫn `dpo`. Ledger được **3 passed**: chuỗi đúng thì verify=True, sửa dòng hoặc để reason trống thì verify=False. Tổng ba nhóm là **12 passed**, không có SKIP, không sửa test bắt buộc.

Sau pytest, mình bật sink thật ở `127.0.0.1:10024`, reset log lần nữa rồi chạy:

```powershell
.\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
.\.venv\Scripts\python.exe -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
```

Script kiểm tra chạy CLI bằng subprocess với đúng module và tham số trên, còn verify gọi trực tiếp. CLI tổng hợp 45 file ticket, đọc hợp lệ 21 hồ sơ, ledger verify=True. Sink không nhận POST. Mình chép log sau lần chạy sang `reports/attack-after.log`, file được **0 byte**.

Lần DPO này thêm 24 entry: 1 search allow, 1 egress deny, 1 allow ánh xạ private store và 21 allow gọi `read_customer`. Ledger lúc đó có 51 dòng. Dòng **29** là `tool=http_post`, `decision=deny`, `on_behalf_of=dpo`, reason `Restricted data cannot cross an egress boundary`.

Để thử việc sửa ledger, mình chép sang file tạm rồi đổi reason ở dòng **26**, không tính lại hash. Bản sao verify=False. Ledger gốc không bị ghi đè và vẫn verify=True.

Đến bước này, file before vẫn chỉ có POST baseline cũ chứa KH-000999. Mình chưa dùng dòng đó làm bằng chứng before cho các lure 902–904b mới thêm. Các lure mới đã qua checker và containment, nhưng lúc ấy chưa có log before riêng. Chi tiết từng biến thể ở `injection-corpus.md`; phần chạy baseline bổ sung nằm cuối báo cáo.

## Nhiệm vụ 4: CP4 và CP5, ngày 12/10/2026

### CP4

Mình dùng `.venv`, thêm thư mục Scripts vào PATH để hook tìm được binary. Các lệnh đã chạy:

```powershell
$env:PATH = "$PWD\.venv\Scripts;$env:PATH"
$env:PRE_COMMIT_HOME = "$PWD\.venv\.cache\pre-commit"
gitleaks version
gitleaks git --config .gitleaks.toml --redact .
gitleaks git --config .gitleaks.toml --redact --verbose .
gitleaks dir --config .gitleaks.toml --redact .
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes -o requirements.lock requirements.txt
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pre_commit install
.\.venv\Scripts\python.exe -m pre_commit run --all-files
.\.venv\Scripts\python.exe -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp
```

Gitleaks **8.30.1** quét history ra **exit 1 / 1 finding / 4 commits**. Finding ở `lab-fake-secret.txt:1`, commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`, rule `lab24-synthetic-token`. Đây là finding mong đợi của lab, không in token thô.

Dir scan ban đầu ra **exit 0 / no leaks found**. Sau khi cài hook thì xuất hiện 415 finding từ cache upstream trong `.venv/`. Mình kiểm metadata, tất cả nằm trong `.venv/`, ở mã mẫu/fixture thuộc phần validate/example của scanner. Sau đó thêm allowlist riêng cho `.venv/` và chạy lại. History vẫn ra **1 finding / exit 1**, dir scan ra **no leaks found / exit 0**.

Riêng `.pytest_cache` và `.pytest_tmp` có cảnh báo permission denied, nên scanner chưa đọc được nội dung hai thư mục đó. Phần xử lý ghi trong `reports/secrets-incident.md`.

Compile lock được **exit 0**, install bằng `--require-hashes` cũng **exit 0**. Pip báo package đã có sẵn. Mình chưa cài thử trên môi trường trống, nên chưa thể nói là đã tải lại và kiểm hash từng wheel.

Pre-commit install thành công, hook **Passed**. Supply-chain test được **3 passed in 0.03s**. Hook upstream dùng `--staged`, vì thế mình có quét thư mục riêng để kiểm cả file hiện tại chưa stage.

Lúc setup có vướng mạng: tải binary trong sandbox không kết nối được. Pip-compile lần đầu báo `WinError 10013`, rồi báo không tìm thấy requests vì không vào được PyPI. Chạy lại với quyền mạng được cấp thì được, không phải sửa constraints. Pip-tools còn warning về mặc định `--strip-extras` ở phiên bản sau, nhưng lệnh vẫn chạy xong.

Cache pre-commit để trong `.venv`. Lần kiểm cuối ở sandbox không đọc được cache hook nên báo `InvalidManifestError`; chạy lại với quyền đã dùng để tải hook thì Passed. Ngoài ra có một lần gõ thừa dấu `)` ở lệnh verify gây `SyntaxError`, sửa rồi chạy lại được True.

### CP5

```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe sink/sink.py --reset
.\.venv\Scripts\python.exe -m pytest tests/ -q --basetemp=.pytest_tmp
```

Lần này output là **46 passed in 6.63s**, không fail/skip. Sink ngoài fixture không chạy trong lúc pytest.

Test xong, script gọi `sink.sink.reset_log()` lần nữa rồi bật server thật bằng `run_in_background()` ở `127.0.0.1:10024`. Sau đó chạy subprocess:

```powershell
.\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
```

CLI exit 0, xử lý **45 ticket, 21 hồ sơ liên quan**. Khi server còn chạy, script dùng `shutil.copyfile('reports/sink.log', 'reports/attack-after.log')`, rồi mới shutdown và đóng cổng. Như vậy log after lấy từ lần replay thật này, không lấy log fixture để lại.

| Phần kiểm tra | Kết quả lúc đó |
|---|---|
| attack-before.log | 299 byte, có POST baseline và KH-000999 giả; giữ nguyên |
| attack-after.log | 0 byte |
| Gọi trực tiếp `verify(Path('reports/ledger.jsonl'))` | True |
| Ledger | 75 dòng, lần mới thêm 24 |
| DPO trong lần mới | 1 search allow, 1 http_post deny, 1 allow ánh xạ store, 21 read_customer tool-call allow |
| Egress deny | `reports/ledger.jsonl:53`, `on_behalf_of=dpo`, classification restricted |

Dòng 53 ghi `reason="Restricted data cannot cross an egress boundary"`, operation `untrusted-egress-request`, agent_id `lab24-agent-38cc72e86f8642bbaaab04119111e07c`. Ledger chỉ có `args_hash` cho URL yêu cầu gửi, không chứa body khách. DPO vẫn đọc được hồ sơ hợp lệ, còn yêu cầu POST thì bị chặn.

Mình đã điền `reports/compliance-mapping.md` bằng nguồn chính thức, có file:dòng thật và ghi giới hạn. `reports/dpia-lite.md` có bốn nội dung đề yêu cầu. Điều/khoản pháp luật để **NOT_VERIFIED** vì chưa đối chiếu toàn văn. Bảng mapping này chưa đủ để kết luận tuân thủ pháp luật.

Cài sạch dependency từ môi trường trống cũng để **NOT_VERIFIED**. Đây không phải bước bắt buộc của lần cài lại từ lock đã làm.

Lúc này ledger và hai attack log vẫn bị `.gitignore` bỏ qua: file có trên máy nhưng chưa stage/commit. Khi chuẩn bị bài nộp cần đưa vào gói theo `SUBMISSION.md`. Không tạo thêm file hướng dẫn.

## Bổ sung trước khi nộp, ngày 12/10/2026

Mình chạy baseline riêng cho đủ bốn biến thể. Dòng 1 của `attack-before.log` giữ nguyên, dòng 2, 3, 4, 5 lần lượt là replay mới của lure 901, 902, 903 và cặp 904/904b.

Mỗi lần có POST thật tới `/reconcile`, một dòng log 299 byte. Records được đối chiếu bằng dict và khớp chính xác hồ sơ KH-000999 trong `data/customers.json`. File before sau khi nối có **1495 byte, 5 dòng**. Bốn dòng thêm này là tái hiện baseline sau khi viết containment, không ghi nhận chúng là log lịch sử trước ngày sửa.

Cách chạy là gọi `_naive_loop(query, get_llm(mock=True, model=None))` với query chuẩn. Trước mỗi lượt, script lấy docs bằng `search_docs` thật, giữ ticket thường và đúng các tên file của biến thể đang thử. Chỉ giá trị trả về của `search_docs` được patch bằng `unittest.mock.patch.object`; `read_customer` và `http_post` vẫn chạy thật.

Sink dùng `run_in_background()` ở localhost, reset từng lượt. Chỉ nối bytes sink log sau khi đã kiểm chứng vào file before. Không tự tạo body POST và không sửa `agent/loop.py` hay runner. Lần đầu script thiếu tham số `model` của `get_llm` nên gặp `TypeError` trước lúc POST. Thêm `model=None`, chạy lại thì đủ bốn lượt thành công.

Sau baseline, mình chạy full suite thêm một lần:

```powershell
python -m pytest tests/ -q --basetemp=.venv/final_pytest_tmp
```

Được **46 passed in 5.92s**, 0 fail/skip. Thư mục tạm trong `.venv` dành riêng cho lần kiểm tra này; lệnh chuẩn để chạy ở terminal vẫn giữ như đề.

Sau pytest mới reset và bật sink, rồi chạy lại CLI mock DPO với query chuẩn. Đọc hợp lệ **21 hồ sơ**, log after **0 byte**. Ledger có **99 dòng**, verify **True**. Deny mới ở dòng **77**, reason `Restricted data cannot cross an egress boundary`, `on_behalf_of=dpo`.

Trước đó terminal người dùng có lần ra **27 passed / 19 errors**. Nguyên nhân là `.pytest_tmp` do tài khoản sandbox tạo, tài khoản `lesan` không có quyền truy cập. Thư mục đó đã được dọn để chạy lệnh chuẩn và tạo lại. Thư mục thử `.pytest_tmp_anh_01` cũng dọn rồi, không đưa vào bài nộp.

`tests/test_cp3_boundaries.py` có 13 test bổ sung, cần nộp cùng code mới tái hiện đủ **46 test**. Test bắt buộc vẫn giữ nguyên. Cache, `.venv` và `reports/sink.log` không nộp.

Compliance mapping đã có link chính thức và chủ đề đối chiếu. Các điều/khoản chưa xác minh thì chưa gán vào bảng, vẫn ghi rõ giới hạn này và chưa kết luận tuân thủ pháp luật.

Đến cuối đã stage đúng **21 file** bài làm, có ba evidence và test bổ sung. Không stage `.venv`, cache hay `sink.log`. `git diff --cached --check` sạch, `pre-commit run --all-files` với các thay đổi đã stage báo **Passed**.

Dir scan cuối ra **no leaks found**, nhưng `.pytest_tmp` thuộc tài khoản người dùng bị permission denied nên chưa tính là đã quét cache đó. Warning LF → CRLF của Git là đổi kiểu xuống dòng, không phải test fail. Bài chưa commit hoặc push, còn bước đọc lại rồi mới thực hiện.
