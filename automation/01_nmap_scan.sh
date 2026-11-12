#!/usr/bin/env bash
# =============================================================================
#  01_nmap_scan.sh — Kịch bản Nmap đầy đủ cho lab Kali -> bee-box (bWAPP)
# -----------------------------------------------------------------------------
#  Cách dùng:
#     chmod +x 01_nmap_scan.sh
#     sudo ./01_nmap_scan.sh 192.168.91.130
#     sudo SKIP_UDP=1 ./01_nmap_scan.sh 192.168.91.130    # bỏ phase UDP
#
#  Kết quả: loot/nmap_<timestamp>/  (mỗi phase 1 bộ .nmap/.xml/.gnmap/.log)
#  Yêu cầu: nmap >= 7.x, chạy bằng root để dùng -sS / -O / -sU
# =============================================================================
set -uo pipefail

TARGET="${1:-192.168.91.130}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="loot/nmap_${STAMP}"
SKIP_UDP="${SKIP_UDP:-0}"
SCRIPT_TIMEOUT="90s"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYA=$'\e[36m'; NC=$'\e[0m'

banner() {
  printf '\n%s================================================================%s\n' "$CYA" "$NC"
  printf '%s  %s%s\n' "$CYA" "$*" "$NC"
  printf '%s================================================================%s\n' "$CYA" "$NC"
}

# run_scan <tên> <nmap args...>
run_scan() {
  local name="$1"; shift
  banner "$name :: nmap $*"
  # -oA xuất .nmap/.xml/.gnmap; tee lưu output màn hình kèm cảnh báo
  nmap "$@" -oA "${OUTDIR}/${name}" 2>&1 | tee "${OUTDIR}/${name}.log"
  printf '%s[+] Đã lưu: %s/%s.{nmap,xml,gnmap}%s\n' "$GRN" "$OUTDIR" "$name" "$NC"
}

# -----------------------------------------------------------------------------
#  0. Tiền kiểm
# -----------------------------------------------------------------------------
if ! command -v nmap >/dev/null 2>&1; then
  echo "${RED}[x] Không tìm thấy nmap. Cài: sudo apt install -y nmap${NC}"; exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "${YEL}[!] Không chạy bằng root: -sS/-O/-sU sẽ bị từ chối."
  echo "    Khuyến nghị: sudo $0 $TARGET${NC}"
fi

mkdir -p "$OUTDIR"

{
  echo "target=$TARGET"
  echo "date=$STAMP"
  echo "attacker=$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "nmap=$(nmap --version | head -1)"
} | tee "${OUTDIR}/_meta.txt"

echo "${GRN}[+] Output dir: ${OUTDIR}${NC}"
echo "${GRN}[+] Target    : ${TARGET}${NC}"

# -----------------------------------------------------------------------------
#  PHASE 1 — HOST DISCOVERY + xác nhận đúng mục tiêu
# -----------------------------------------------------------------------------
run_scan "01_ping_sweep" -sn -n "$(echo "$TARGET" | awk -F. '{print $1"."$2"."$3".0/24"}')"
run_scan "01_host_probe" -sn -PR -PS22,80,443,3306 -PA80,443 -PE -PP "$TARGET"

# -----------------------------------------------------------------------------
#  PHASE 2 — PORT SCANNING
# -----------------------------------------------------------------------------
# 2a. Top 1000 TCP, SYN scan, aggressive timing
run_scan "02_tcp_top1000" -sS -T4 -Pn --top-ports 1000 --reason --open "$TARGET"

# 2b. Toàn bộ 65535 TCP — bắt buộc để không sót dịch vụ ngoài top-1000
run_scan "02_tcp_full" -sS -p- -T4 -Pn --min-rate 1500 --max-retries 2 \
  --reason --open "$TARGET"

# 2c. ACK scan — map firewall (unfiltered vs filtered), không tìm port mở
run_scan "02_ack_firewall_map" -sA -p 1-1000 -T4 -Pn "$TARGET"

# 2d. UDP top 50 (chậm; có thể bỏ bằng SKIP_UDP=1)
if [[ "$SKIP_UDP" != "1" ]]; then
  run_scan "02_udp_top50" -sU --top-ports 50 -T4 -Pn --reason "$TARGET"
fi

# -----------------------------------------------------------------------------
#  PHASE 3 — SERVICE / VERSION DETECTION
# -----------------------------------------------------------------------------
PORTS="22,80,443,3306,111,8080"
run_scan "03_version_all" -sV --version-all -sC -p "$PORTS" \
  --script banner --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# RPC (chỉ có ý nghĩa nếu 111 mở)
run_scan "03_rpc" -sV -sR -p 111 "$TARGET"

# -----------------------------------------------------------------------------
#  PHASE 4 — OS FINGERPRINT
# -----------------------------------------------------------------------------
run_scan "04_os" -O --osscan-guess --osscan-limit --max-os-tries 2 \
  -p "$PORTS" "$TARGET"

# -----------------------------------------------------------------------------
#  PHASE 5 — NSE ENUMERATION (an toàn trước, intrusive sau)
# -----------------------------------------------------------------------------
# 5a. default + safe + discovery + version
run_scan "05_nse_safe" -sV -p "$PORTS" \
  --script "default or safe or discovery or version" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# 5b. Web (bee-box là web app -> ưu tiên)
run_scan "05_nse_http" -sV -p 80,443 --script \
"http-title,http-headers,http-methods,http-server-header,http-robots.txt,\
http-enum,http-git,http-config-backup,http-backup-finder,http-php-version,\
http-cookie-flags,http-security-headers,http-cors,http-auth,http-auth-finder,\
http-phpmyadmin-dir-traversal,http-webdav-scan,http-put,http-userdir-enum,\
http-trace,http-aspnet-debug" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# 5c. MySQL
run_scan "05_nse_mysql" -sV -p 3306 --script \
"mysql-info,mysql-empty-password,mysql-enum,mysql-variables,mysql-databases,mysql-users" \
  --script-args 'mysqluser=root,mysqlpass=bug' \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# 5d. SSH
run_scan "05_nse_ssh" -p 22 --script \
"ssh-hostkey,ssh-auth-methods,ssh2-enum-algos,ssh-publickey-acceptance" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# 5e. SSL/TLS
run_scan "05_nse_ssl" -p 443 --script \
"ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,ssl-poodle,ssl-ccs-injection" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# 5f. FTP / SMB / NFS — chạy vô hại nếu port không mở (nmap tự bỏ qua)
run_scan "05_nse_ftp" -p 21 --script "ftp-anon,ftp-syst,ftp-vsftpd-backdoor" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"
run_scan "05_nse_smb" -p 139,445 --script \
"smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode,smb-vuln-*" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"
run_scan "05_nse_nfs" -p 111 --script "rpcinfo,nfs-ls,nfs-showmount,nfs-statfs" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# -----------------------------------------------------------------------------
#  PHASE 6 — VULNERABILITY (NSE category = vuln)
# -----------------------------------------------------------------------------
run_scan "06_nse_vuln" -sV -p "$PORTS" --script vuln \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# Web app: SQLi / XSS / CSRF / upload
run_scan "06_nse_webapp" -p 80 --script \
"http-sql-injection,http-stored-xss,http-dom-based-xss,http-csrf,\
http-fileupload-exploiter,http-shellshock" \
  --script-args 'http-sql-injection.maxdepth=3' \
  --script-timeout "180s" "$TARGET"

# Apache cụ thể
run_scan "06_nse_apache" -p 80 --script \
"http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2012-1823,\
http-vuln-cve2017-5638" \
  --script-timeout "$SCRIPT_TIMEOUT" "$TARGET"

# -----------------------------------------------------------------------------
#  PHASE 7 — TỔNG HỢP
# -----------------------------------------------------------------------------
banner "TỔNG HỢP PORT MỞ"
grep -hE "^[0-9]+/(tcp|udp)" "${OUTDIR}"/*.nmap 2>/dev/null | sort -u \
  | tee "${OUTDIR}/_open_ports.txt"

banner "CHUYỂN XML -> HTML (nếu có xsltproc)"
if command -v xsltproc >/dev/null 2>&1; then
  for f in "${OUTDIR}"/*.xml; do
    xsltproc "$f" -o "${f%.xml}.html" 2>/dev/null && echo "[+] ${f%.xml}.html"
  done
else
  echo "[i] Không có xsltproc: sudo apt install -y xsltproc"
fi

banner "HOÀN TẤT"
echo "Output: ${OUTDIR}"
echo "Gợi ý đọc nhanh:"
echo "  less ${OUTDIR}/_open_ports.txt"
echo "  grep -i 'VULNERABLE' ${OUTDIR}/*.log"
echo "  grep -iE 'open|filtered' ${OUTDIR}/02_tcp_full.nmap"
