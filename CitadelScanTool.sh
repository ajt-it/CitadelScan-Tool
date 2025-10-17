#!/usr/bin/env bash
# ============================================================================ #
#  🛡️ CitadelScanTool.sh — Audit non-intrusif Unix/Linux (Citadel IT Solutions)
#  Version: 3.0
#  Date   : Octobre 2025
#  Licence: Citadel Open License (non-commerciale) – Citadel IT Solutions
#
#  Description:
#    - Lecture seule — collecte des informations d'hardening / sécurité
#    - Profils : isaca | cis | full
#    - Sorties : TXT (toujours), HTML (optionnel)
#
#  Usage (exemples):
#    sudo ./CitadelScanTool.sh --profile=isaca --output=/tmp/audit --html --banner=auto
#
#  NOTE: Aucune modification n’est effectuée (read-only).
# ============================================================================ #

set -o pipefail
IFS=$' \t\n'

# (Locale par défaut pour éviter les warnings setlocale, tout en gardant Unicode)
export LANG=${LANG:-C.UTF-8}
export LC_ALL=${LC_ALL:-C.UTF-8}

# ------------------------- Options ------------------------- #
PROFILE="full"         # isaca | cis | full
OUTDIR="."
GEN_HTML=0
NO_COLOR=0
SUMMARY_ONLY=0
BANNER_SIZE="auto"     # auto | mini | medium | wide | none

for arg in "$@"; do
  case "$arg" in
    --profile=*) PROFILE="${arg#*=}" ;;
    --output=*)  OUTDIR="${arg#*=}" ;;
    --html)      GEN_HTML=1 ;;
    --no-color)  NO_COLOR=1 ;;
    --summary)   SUMMARY_ONLY=1 ;;
    --banner=*)  BANNER_SIZE="${arg#*=}" ;;
    --help|-h)
      cat <<'EOF'
CitadelScanTool.sh — Audit read-only
Options:
  --profile=<isaca|cis|full>             Profil de contrôles (défaut: full)
  --output=<dir>                         Répertoire de sortie (défaut: .)
  --html                                 Générer un rapport HTML (en plus du TXT)
  --banner=<auto|mini|medium|wide|none>  Taille de bannière terminal (défaut: auto)
  --no-color                             Désactiver les couleurs/emoji
  --summary                              Écrire seulement le résumé/score
  --help                                 Afficher cette aide
EOF
      exit 0
      ;;
  esac
done

# ------------------------- Couleurs & helpers ------------------------- #
if [[ $NO_COLOR -eq 1 ]]; then
  BLUE=""; GREEN=""; YELLOW=""; RED=""; ORANGE=""; SILVER=""; NC=""
else
  BLUE=$'\033[0;34m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'
  ORANGE=$'\033[38;5;208m'; SILVER=$'\033[1;37m'; NC=$'\033[0m'
fi
EMOJI_OK="✅"; EMOJI_WARN="⚠️"; EMOJI_BAD="❌"; EMOJI_INFO="ℹ️"

have()      { command -v "$1" >/dev/null 2>&1; }
as_root()   { [[ $EUID -eq 0 ]]; }
stamp()     { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_term_cols(){ tput cols 2>/dev/null || echo 80; }
_center()   { local cols=$(_term_cols) line="$1" pad len; len=${#line}; (( cols>len )) && pad=$(( (cols-len)/2 )) || pad=0; printf "%*s%s\n" "$pad" "" "$line"; }

# ------------------------- Bannière ASCII (figlet si dispo) ------------------------- #
banner_render() {
  [[ "$BANNER_SIZE" == "none" ]] && return 0
  local cols=$(_term_cols)

  if command -v figlet >/dev/null 2>&1; then
    figlet -w "$cols" "CitadelScan Tool" | while IFS= read -r line; do _center "$line"; done
  else
    _center "============================================================"
    _center "                    CitadelScan Tool                         "
    _center "============================================================"
  fi
  echo
}

# ------------------------- Scoring ------------------------- #
weight_of() {
  case "$1" in
    pam|ssh|emptyPwd|sudoers|suidsgid|worldwritable) echo 10 ;;
    selinux|grub|firewall|password_age|mounts|auditd|logs) echo 8 ;;
    net|icmp|ntp|legacyproto|snmp) echo 6 ;;
    ipv6|banner) echo 4 ;;
    cron|usb|fail2ban|updates) echo 3 ;;
    packages) echo 2 ;;
    *) echo 5 ;;
  esac
}
points_of() {
  case "$1" in
    OK) echo 100 ;;
    INFO) echo 80 ;;
    WARN|SKIP) echo 50 ;;
    FAIL|ERROR) echo 0 ;;
    *) echo 50 ;;
  esac
}
SCORE_NUM=0; SCORE_DEN=0

# --- Résumé express : compteurs & log des risques ---
declare -i COUNT_OK=0 COUNT_INFO=0 COUNT_WARN=0 COUNT_FAIL=0 COUNT_SKIP=0
ISSUE_LOG="$(mktemp -t citadelscan_issues.XXXXXX)"
trap 'rm -f "$ISSUE_LOG"' EXIT

add_score() {
  local id="$1"; local status="$2"
  local w=$(weight_of "$id")
  local p=$(points_of "$status")
  SCORE_NUM=$((SCORE_NUM + w * p))
  SCORE_DEN=$((SCORE_DEN + w * 100))
  case "$status" in
    OK)    COUNT_OK+=1 ;;
    INFO)  COUNT_INFO+=1 ;;
    WARN|SKIP) COUNT_WARN+=1 ;;
    FAIL|ERROR) COUNT_FAIL+=1 ;;
  esac
}

# ------------------------- Profils ------------------------- #
run_check_by_profile() {
  local id="$1"
  case "$PROFILE" in
    isaca)
      case "$id" in
        ssh|selinux|grub|net|firewall|ntp|cron|emptyPwd|password_age|pam|icmp|ipv6|sudoers|logs|auditd|mounts|legacyproto|snmp|suidsgid|worldwritable|banner|updates) return 0 ;;
        *) return 1 ;;
      esac ;;
    cis)
      case "$id" in
        selinux|ssh|pam|password_age|emptyPwd|grub|net|firewall|ntp|icmp|ipv6|sudoers|mounts|suidsgid|worldwritable|logs|auditd|banner|updates) return 0 ;;
        *) return 1 ;;
      esac ;;
    full|*) return 0 ;;
  esac
}

# ------------------------- Impression helpers ------------------------- #
section(){ echo ""; echo "## $1"; echo "----------------------------------------------------------------"; }
note() { echo -e "${BLUE}${EMOJI_INFO} $*${NC}"; }
good() { echo -e "${GREEN}${EMOJI_OK} $*${NC}"; }
warn() { echo -e "${YELLOW}${EMOJI_WARN} $*${NC}"; echo -e "[WARN]\t$*" >> "$ISSUE_LOG"; }
bad()  { echo -e "${RED}${EMOJI_BAD} $*${NC}";   echo -e "[FAIL]\t$*" >> "$ISSUE_LOG"; }

# ---------- Pretty summary helpers ----------
_box_width() { tput cols 2>/dev/null || echo 80; }
_pad() { local s="$1" w="$2" l=${#1}; (( l<w )) && printf "%s%*s" "$s" $((w-l)) "" || printf "%s" "$s"; }
_print_line() { local w="$2"; printf "│ %s │\n" "$(_pad "$1" $((w-4)))"; }
_hline() { local w="$1"; printf "┌%*s┐\n" $((w-2)) "" | tr ' ' '─'; }
_mline() { local w="$1"; printf "├%*s┤\n" $((w-2)) "" | tr ' ' '─'; }
_bline() { local w="$1"; printf "└%*s┘\n" $((w-2)) "" | tr ' ' '─'; }
top_risks() {  # FAIL d'abord puis WARN, max N
  local N="${1:-10}"
  { grep -E '^\[FAIL\]' "$ISSUE_LOG"; grep -E '^\[WARN\]' "$ISSUE_LOG"; } 2>/dev/null \
    | sed -E "s/^\[FAIL\]\t/${EMOJI_BAD} CRITIQUE: /; s/^\[WARN\]\t/${EMOJI_WARN} AVERT.: /" \
    | head -n "$N"
}

# ------------------------- Initialisation ------------------------- #
host=$(hostname 2>/dev/null || echo unknown)
ts=$(date +"%Y%m%d_%H%M%S")
mkdir -p "$OUTDIR" || { echo "Impossible de créer $OUTDIR"; exit 1; }
REPORT_BASE="CitadelScan_Audit_${host}_${ts}"
REPORT_TXT="${OUTDIR%/}/${REPORT_BASE}.txt"
REPORT_HTML="${OUTDIR%/}/${REPORT_BASE}.html"

# ------------------------- Bannière (terminal) ------------------------- #
[[ $SUMMARY_ONLY -eq 0 ]] && banner_render

# ========================= MAIN REPORT ========================= #
{
echo "============================================================"
echo "🛡️  CITADELSCAN - Rapport d'audit (Citadel IT Solutions)"
echo "============================================================"
echo "Horodatage (UTC): $(stamp)"
echo "Hôte            : $host"
echo "Utilisateur     : $(whoami)"
echo "Profil          : $PROFILE"
echo "Commande        : $0 $*"
echo ""
if ! as_root; then
  warn "Certaines vérifications nécessitent les privilèges root. Lancez avec sudo pour un audit complet."
fi

# 1) Bootloader / GRUB
if run_check_by_profile grub; then
  section "Bootloader — GRUB/GRUB2 & /boot"
  id="grub"
  found_cfg=0; prot_ok=0; ro_ok=0
  for cfg in /boot/grub/grub.conf /boot/grub/menu.lst /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
    if [[ -f "$cfg" ]]; then
      found_cfg=1
      echo "Fichier: $cfg"
      if grep -Eq 'password_pbkdf2|password\s+--md5' "$cfg"; then
        good "Protection GRUB par mot de passe détectée dans $cfg"; prot_ok=1
      else
        warn "Aucun mot de passe détecté dans $cfg"
      fi
    fi
  done
  [[ $found_cfg -eq 0 ]] && note "Aucun fichier GRUB standard trouvé."
  ro_opts=$(awk '$2=="/boot"{print $4}' /proc/mounts 2>/dev/null || true)
  if echo "$ro_opts" | grep -qw ro; then good "/boot monté en lecture seule (ro)"; ro_ok=1
  else warn "/boot n'est pas monté en lecture seule"; fi
  [[ $prot_ok -eq 1 && $ro_ok -eq 1 ]] && add_score "$id" "OK" || { [[ $prot_ok -eq 1 || $ro_ok -eq 1 ]] && add_score "$id" "WARN" || add_score "$id" "FAIL"; }
fi

# 2) Services & Ports
if run_check_by_profile net; then
  section "Services & Ports"
  id="net"
  initd="unknown"; { [[ -f /run/systemd/system ]] || [[ "$(ps -p1 -o comm=)" == "systemd" ]]; } && initd="systemd"
  echo "Init system: $initd"
  if [[ $initd == "systemd" ]] && have systemctl; then
    echo "Services activés (extrait):"
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | sed -n '1,150p'
    echo ""
    echo "Services en cours (extrait):"
    systemctl list-units --type=service --state=running --no-pager 2>/dev/null | sed -n '1,150p'
  else
    if have chkconfig; then echo "chkconfig (runlevel 3 on):"; /sbin/chkconfig --list 2>/dev/null | grep '3:on' || true
    else note "'chkconfig' non disponible"; fi
  fi
  echo ""; echo "Ports à l'écoute (extrait):"
  if have ss; then ss -tulpen 2>/dev/null | head -n 200 || true
  elif have netstat; then netstat -tulpn 2>/dev/null | head -n 200 || true
  else note "Aucun 'ss' ou 'netstat' trouvé"; fi
  add_score "$id" "INFO"
fi

# 3) SSH
if run_check_by_profile ssh; then
  section "SSH — Configuration & protections"
  id="ssh"; SSH_CFG="/etc/ssh/sshd_config"
  [[ -f "$SSH_CFG" ]] && { echo "Fichier: $SSH_CFG"; grep -Ei '^\s*(PermitRootLogin|PasswordAuthentication|Port|ListenAddress|AllowUsers|PermitEmptyPasswords|Protocol)\b' "$SSH_CFG" | sed 's/^/  /' || true; } \
                       || note "sshd_config introuvable ($SSH_CFG)"
  if have sshd && sshd -T >/dev/null 2>&1; then
    echo ""; echo "Paramètres effectifs (sshd -T):"
    sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|port|allowusers|permitemptypasswords)\b' | sed 's/^/  /' || true
  fi
  permit=""
  if have sshd && sshd -T >/dev/null 2>&1; then
    permit=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2; exit}')
  elif [[ -f "$SSH_CFG" ]]; then
    permit=$(awk '/^[[:space:]]*PermitRootLogin/{print tolower($2); exit}' "$SSH_CFG" 2>/dev/null || true)
  fi
  ssh_status="INFO"
  if [[ -n "$permit" ]]; then
    if [[ "$permit" == "no" || "$permit" == "prohibit-password" || "$permit" == "forced-commands-only" ]]; then
      good "PermitRootLogin = $permit (recommandé)"; ssh_status="OK"
    else
      bad "PermitRootLogin = $permit (risque accru)"; ssh_status="FAIL"
    fi
  else note "Impossible de déterminer PermitRootLogin"; ssh_status="INFO"; fi
  if systemctl is-active --quiet fail2ban 2>/dev/null || pgrep -f "fail2ban-server" >/dev/null 2>&1; then good "Fail2ban détecté/actif"
  elif pgrep -f "denyhosts" >/dev/null 2>&1; then good "DenyHosts détecté"
  else warn "Fail2ban / DenyHosts non détecté (recommandé)"; fi
  add_score "$id" "$ssh_status"
fi

# 4) PAM
if run_check_by_profile pam; then
  section "PAM — Politique mots de passe"
  id="pam"; files=("/etc/pam.d/system-auth" "/etc/pam.d/common-password"); found=0; lines=""
  for f in "${files[@]}"; do
    if [[ -f "$f" ]]; then
      found=1; echo "Fichier: $f"
      l=$(grep -E 'pam_pwquality.so|pam_cracklib.so|remember=' "$f" 2>/dev/null || true)
      [[ -n "$l" ]] && { echo "$l" | sed 's/^/  /'; lines+="$l"$'\n'; } || echo "  (aucune ligne pwquality/cracklib/remember)"
    fi
  done
  if [[ $found -eq 0 ]]; then note "Fichiers PAM non trouvés"; add_score "$id" "INFO"
  else
    if echo "$lines" | grep -q 'remember=' && echo "$lines" | grep -q -E 'pam_pwquality|pam_cracklib'; then good "Complexité & historique (remember) détectés"; add_score "$id" "OK"
    else warn "Règles PAM incomplètes (ajouter pam_pwquality + remember=N)"; add_score "$id" "WARN"; fi
  fi
fi

# 5) Password aging / empty passwords
if run_check_by_profile password_age; then
  section "Mots de passe — Aging (chage)"
  if as_root && have chage; then
    getent passwd | cut -d: -f1 | head -n 80 | while read -r u; do
      echo "Utilisateur: $u"; chage -l "$u" 2>/dev/null | sed 's/^/  /'
    done; add_score "password_age" "INFO"
  else note "chage ou privilèges root manquants"; add_score "password_age" "SKIP"; fi
fi
if run_check_by_profile emptyPwd; then
  id="emptyPwd"
  if as_root; then
    empties=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empties" ]]; then bad "Comptes MDP vide: $empties"; add_score "$id" "FAIL"
    else good "Aucun compte avec MDP vide"; add_score "$id" "OK"; fi
  else note "Vérif /etc/shadow impossible sans root"; add_score "$id" "SKIP"; fi
fi

# 6) SELinux / AppArmor
if run_check_by_profile selinux; then
  section "SELinux / AppArmor"
  id="selinux"
  if have getenforce; then
    st=$(getenforce 2>/dev/null || true); echo "getenforce: ${st:-indisponible}"
    if [[ "$st" == "Enforcing" ]]; then good "SELinux Enforcing"; add_score "$id" "OK"
    elif [[ "$st" == "Permissive" ]]; then warn "SELinux Permissive"; add_score "$id" "WARN"
    else bad "SELinux désactivé ou absent"; add_score "$id" "FAIL"; fi
  else
    if [[ -d /etc/apparmor.d ]]; then note "AppArmor présent"; add_score "$id" "INFO"
    else note "SELinux/AppArmor non détecté"; add_score "$id" "INFO"; fi
  fi
fi

# 7) Pare-feu
if run_check_by_profile firewall; then
  section "Pare-feu"
  id="firewall"
  if systemctl is-active --quiet firewalld 2>/dev/null; then good "firewalld actif"; firewall-cmd --list-all 2>/dev/null | sed 's/^/  /' || true; add_score "$id" "OK"
  elif have ufw; then echo "ufw status:"; ufw status 2>/dev/null | sed 's/^/  /' || true; add_score "$id" "INFO"
  elif have iptables-save; then echo "iptables-save (extrait):"; iptables-save 2>/dev/null | sed -n '1,200p' || true; add_score "$id" "INFO"
  else warn "Aucun pare-feu détecté"; add_score "$id" "WARN"; fi
fi

# 8) NTP / Chrony
if run_check_by_profile ntp; then
  section "NTP / Chrony"
  id="ntp"
  if have ntpq; then echo "ntpq -p:"; ntpq -p 2>/dev/null | sed 's/^/  /' || true; add_score "$id" "OK"
  elif have chronyc; then echo "chronyc sources:"; chronyc sources 2>/dev/null | sed 's/^/  /' || true; add_score "$id" "OK"
  elif have timedatectl; then timedatectl show -p NTPSynchronized -p TimeUSec -p NTP 2>/dev/null | sed 's/^/  /' || true; add_score "$id" "INFO"
  else note "Pas d'outil NTP/chrony/timedatectl"; add_score "$id" "SKIP"; fi
fi

# 9) ICMP sysctl
if run_check_by_profile icmp; then
  section "ICMP (sysctl) — ignore echo / broadcasts"
  id="icmp"
  a=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null || echo "NA")
  b=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null || echo "NA")
  echo "net.ipv4.icmp_echo_ignore_all = $a"
  echo "net.ipv4.icmp_echo_ignore_broadcasts = $b"
  if [[ "$a" == "1" && "$b" == "1" ]]; then good "ICMP echo & broadcasts ignorés"; add_score "$id" "OK"
  elif [[ "$a" == "NA" || "$b" == "NA" ]]; then note "Valeurs sysctl indisponibles"; add_score "$id" "INFO"
  else warn "ICMP ignore non entièrement activé"; add_score "$id" "WARN"; fi
fi

# 10) IPv6
if run_check_by_profile ipv6; then
  section "IPv6"
  id="ipv6"
  if have sysctl; then
    val=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "NA")
    echo "net.ipv6.conf.all.disable_ipv6 = $val"
    if [[ "$val" == "1" ]]; then good "IPv6 désactivé globalement"; add_score "$id" "OK"
    else note "IPv6 activé (vérifier usage/pol.)"; add_score "$id" "INFO"; fi
  else note "sysctl non disponible"; add_score "$id" "SKIP"; fi
fi

# 11) Cron / at
if run_check_by_profile cron; then
  section "Cron / At — contrôle d'accès"
  id="cron"
  [[ -f /etc/cron.allow ]] && { echo "/etc/cron.allow (extrait):"; head -n 10 /etc/cron.allow | sed 's/^/  /'; }
  [[ -f /etc/cron.deny  ]] && { echo "/etc/cron.deny  (extrait):"; head -n 10 /etc/cron.deny  | sed 's/^/  /'; }
  [[ -f /etc/at.allow   ]] && { echo "/etc/at.allow   (extrait):"; head -n 10 /etc/at.allow   | sed 's/^/  /'; }
  [[ -f /etc/at.deny    ]] && { echo "/etc/at.deny    (extrait):"; head -n 10 /etc/at.deny    | sed 's/^/  /'; }
  if [[ ! -f /etc/cron.allow && ! -f /etc/cron.deny ]]; then
    warn "Aucun cron.allow/cron.deny trouvé"; add_score "$id" "WARN"
  else add_score "$id" "INFO"; fi
fi

# 12) Fail2ban
if run_check_by_profile fail2ban; then
  section "Fail2ban — jails & bannissements"
  id="fail2ban"
  if have fail2ban-client; then
    fail2ban-client status 2>/dev/null | sed 's/^/  /' || true
    jails=$(fail2ban-client status 2>/dev/null | awk -F: '/Jail/{print $2}' | tr ',' ' ' | tr -d ' ')
    for j in $jails; do [[ -n "$j" ]] && { echo "Jail: $j"; fail2ban-client status "$j" 2>/dev/null | sed 's/^/  /' || true; }; done
    add_score "$id" "INFO"
  else note "fail2ban non installé"; add_score "$id" "SKIP"; fi
fi

# 13) USB / udev
if run_check_by_profile usb; then
  section "USB — inventaire & règles udev"
  id="usb"
  if have lsusb; then lsusb 2>/dev/null | sed 's/^/  /' || true
  else note "lsusb non trouvé"; fi
  echo "Fichiers udev (.rules) contenant 'usb' (extrait):"
  for d in /etc/udev/rules.d /lib/udev/rules.d; do
    [[ -d "$d" ]] && grep -Il "usb" "$d"/*.rules 2>/dev/null | head -n 20 | sed 's/^/  /' || true
  done
  add_score "$id" "INFO"
fi

# 14) Paquets / Updates
if run_check_by_profile packages || run_check_by_profile updates; then
  section "Paquets / Outils d'update"
  id="updates"
  if have rpm; then rpm -qa | head -n 50 | sed 's/^/  /' || true; fi
  if have dpkg-query; then dpkg-query -W -f='${Package} ${Version}\n' | head -n 50 | sed 's/^/  /' || true; fi
  if have dnf || have yum || have apt || have zypper; then
    good "Gestionnaire de mises à jour présent (dnf/yum/apt/zypper)"; add_score "$id" "INFO"
  else
    warn "Aucun outil de mise à jour standard détecté"; add_score "$id" "WARN"
  fi
fi

# 15) sudoers
if run_check_by_profile sudoers; then
  section "Sudoers — règles (lecture)"
  id="sudoers"
  if [[ -r /etc/sudoers ]]; then
    visudo -c >/dev/null 2>&1 && good "sudoers valide (visudo -c)"
    egrep -i '(^%?wheel|NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/  /' || true
    add_score "$id" "INFO"
  else
    note "sudoers non lisible"; add_score "$id" "SKIP"
  fi
fi

# 16) SUID/SGID sensibles
if run_check_by_profile suidsgid; then
  section "Fichiers SUID/SGID sensibles (échantillon)"
  id="suidsgid"
  if as_root; then
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | egrep -i '(passwd|su|sudo|mount|umount|chsh|chfn|newgrp|ping|traceroute|nmap)' | head -n 100 | sed 's/^/  /' || true
    add_score "$id" "INFO"
  else note "Nécessite root"; add_score "$id" "SKIP"; fi
fi

# 17) World-writable
if run_check_by_profile worldwritable; then
  section "Répertoires world-writable (échantillon)"
  id="worldwritable"
  if as_root; then
    find / -xdev -type d -perm -0002 2>/dev/null | head -n 50 | sed 's/^/  /'
  else
    note "Nécessite root"
  fi
  add_score "$id" "INFO"
fi

# 18) Montages & options
if run_check_by_profile mounts; then
  section "Systèmes de fichiers & options de montage"
  id="mounts"
  mount | sed 's/^/  /' | head -n 200
  for p in /tmp /var /var/tmp /home; do
    if grep -E "[[:space:]]$p[[:space:]]" /proc/mounts >/dev/null 2>&1; then
      opts=$(awk -v p="$p" '$2==p{print $4}' /proc/mounts)
      echo "$p options: $opts"
      for f in nodev nosuid noexec; do
        echo "$opts" | grep -qw "$f" || warn "$p n'a pas l'option $f"
      done
    fi
  done
  [[ -f /etc/crypttab ]] && good "Chiffrement détecté (crypttab présent)"
  add_score "$id" "INFO"
fi

# 19) Logs / journald / rsyslog
if run_check_by_profile logs; then
  section "Logs — journald / rsyslog"
  id="logs"
  systemctl is-active --quiet rsyslog 2>/dev/null && good "rsyslog actif"
  systemctl is-active --quiet systemd-journald 2>/dev/null && good "journald actif"
  [[ -d /var/log ]] && ls -lh /var/log 2>/dev/null | head -n 30 | sed 's/^/  /'
  add_score "$id" "INFO"
fi

# 20) auditd
if run_check_by_profile auditd; then
  section "auditd — statut"
  id="auditd"
  if systemctl is-active --quiet auditd 2>/dev/null; then good "auditd actif"; add_score "$id" "OK"
  else warn "auditd non actif"; add_score "$id" "WARN"; fi
fi

# 21) Protocoles hérités
if run_check_by_profile legacyproto; then
  section "Protocoles hérités (telnet, rsh, ftp)"
  id="legacyproto"
  for svc in telnet.socket telnet.service rsh.service rlogin.service vsftpd.service ftp.service; do
    systemctl is-enabled --quiet "$svc" 2>/dev/null && bad "$svc activé"
  done
  egrep -i '^(telnet|rsh|rlogin)\b' /etc/inetd.conf 2>/dev/null | sed 's/^/  /'
  add_score "$id" "INFO"
fi

# 22) SNMP (correction sed -> awk)
if run_check_by_profile snmp; then
  section "SNMP — community strings (v2c) (lecture)"
  id="snmp"
  for f in /etc/snmp/snmpd.conf /usr/local/etc/snmp/snmpd.conf; do
    [[ -f "$f" ]] && awk -v FF="$f" '/^(rocommunity|rwcommunity)/{print "  (" FF ") " $0}' "$f"
  done
  add_score "$id" "INFO"
fi

# 23) Bannières légales
if run_check_by_profile banner; then
  section "Bannières de connexion (issue/issue.net)"
  id="banner"
  [[ -s /etc/issue     ]] && good "/etc/issue présent (non vide)" || warn "/etc/issue absent ou vide"
  [[ -s /etc/issue.net ]] && note "/etc/issue.net présent (bannières SSH)" || note "/etc/issue.net absent"
  add_score "$id" "INFO"
fi

echo ""; echo "============================================================"
echo "🛡️  FIN DES VÉRIFICATIONS"
echo "============================================================"

# Résumé & score (texte intégral, inchangé)
section "Résumé & Score"
if [[ $SCORE_DEN -gt 0 ]]; then
  SCORE=$(( (SCORE_NUM * 100) / SCORE_DEN ))
  echo "Score global (pondéré) : $SCORE / 100"
else
  echo "Score global : N/A"
fi
echo ""
echo "Conseils:"
echo " - Exécuter en root pour des résultats complets (sudo)."
echo " - Profil 'isaca' → contrôles ISACA-centrés."
echo " - Profil 'cis'   → contrôles proches CIS benchmark."
echo " - Profil 'full'  → tous les contrôles."
echo ""

# --- AJOUT MINIMAL #1 : PERSISTER l'état pour le shell parent (corrige N/A) ---
STATE_FILE="${OUTDIR%/}/${REPORT_BASE}.state"
{
  echo "SCORE_NUM=$SCORE_NUM"
  echo "SCORE_DEN=$SCORE_DEN"
  echo "COUNT_OK=$COUNT_OK"
  echo "COUNT_INFO=$COUNT_INFO"
  echo "COUNT_WARN=$COUNT_WARN"
  echo "COUNT_FAIL=$COUNT_FAIL"
  echo "COUNT_SKIP=$COUNT_SKIP"
} > "$STATE_FILE"

} | tee "${REPORT_TXT}" >/dev/null

# --- AJOUT MINIMAL #2 : RECHARGER l'état après le pipe ---
[ -f "${OUTDIR%/}/${REPORT_BASE}.state" ] && . "${OUTDIR%/}/${REPORT_BASE}.state"

# ------------------------- Rapport HTML (ASCII header via figlet si dispo) ------------------------- #
if [[ $GEN_HTML -eq 1 && $SUMMARY_ONLY -eq 0 ]]; then
  TITLE="CitadelScan — Rapport"
  CSS=$'body{font-family:Arial,Helvetica,sans-serif;background:#0b1220;color:#e5e7eb;padding:24px}h1{color:#FBBF24;text-align:center;margin:16px 0 8px}.pre{background:#0f172a;border-radius:8px;padding:12px;overflow:auto;border:1px solid #1f2937;white-space:pre-wrap}.header{display:flex;flex-direction:column;align-items:center;gap:8px;margin-bottom:16px}.meta{color:#9ca3af;text-align:center;font-size:14px}.ascii{font-family:monospace;line-height:1.05;white-space:pre;text-align:center;margin:6px 0 2px}'
  if command -v figlet >/dev/null 2>&1; then
    ASCII_HEADER="$(figlet -w 100 "CitadelScan Tool")"
  else
    ASCII_HEADER="===================== CitadelScan Tool ====================="
  fi
  {
    echo "<!doctype html><html><head><meta charset='utf-8'><title>${TITLE}</title>"
    echo "<style>${CSS}</style></head><body>"
    echo "<div class='header'><pre class='ascii'>${ASCII_HEADER}</pre>"
    echo "<h1>${TITLE}</h1>"
    echo "<div class='meta'>Host: ${host} • UTC: $(stamp)</div></div><div class='pre'>"
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "${REPORT_TXT}"
    echo "</div></body></html>"
  } > "${REPORT_HTML}"
  echo "HTML report: ${REPORT_HTML}"
fi

# ---------- Résumé express premium (boîte lisible + top risques) ----------
sleep 2
command -v clear >/dev/null 2>&1 && clear

if [[ ${SCORE_DEN:-0} -gt 0 ]]; then
  SCORE=$(( (SCORE_NUM * 100) / SCORE_DEN ))
else
  SCORE="N/A"
fi

SUMMARY_TXT="${OUTDIR%/}/${REPORT_BASE}_SUMMARY.txt"
W=$(_box_width); (( W<60 )) && W=60
TITLE="CitadelScan — Résumé de l'audit"
SUB="Host: ${host} • UTC: $(stamp)"

_hline "$W"
_print_line "$TITLE" "$W"
_mline "$W"
_print_line "Score global : ${SCORE}/100" "$W"
_print_line "Recommandations : Total=$((COUNT_WARN+COUNT_FAIL))  |  Critiques=${COUNT_FAIL} ${EMOJI_BAD}  |  Avertissements=${COUNT_WARN} ${EMOJI_WARN}" "$W"
_print_line "Infos : ${COUNT_INFO}  |  OK : ${COUNT_OK}" "$W"
_mline "$W"
_print_line "Principaux risques :" "$W"
while IFS= read -r L; do
  [[ -n "$L" ]] && _print_line "$L" "$W"
done < <(top_risks 10)
_mline "$W"
_print_line "$SUB" "$W"
_bline "$W"

echo ""
echo "Rapports complets :"
echo " - TXT : ${REPORT_TXT}"
[[ -n "${REPORT_HTML}" && -f "${REPORT_HTML}" ]] && echo " - HTML: ${REPORT_HTML}"
echo " - SUMMARY : ${SUMMARY_TXT}"
echo "============================================================"

# Fichier résumé (propre, sans codes ANSI)
{
  echo "# CitadelScan — Résumé"
  echo "- Hôte: ${host}"
  echo "- Date (UTC): $(stamp)"
  echo "- Profil: ${PROFILE}"
  echo "- Score global: ${SCORE}/100"
  echo "- Recommandations: total=$((COUNT_WARN+COUNT_FAIL)), critiques=${COUNT_FAIL}, avertissements=${COUNT_WARN}, infos=${COUNT_INFO}, ok=${COUNT_OK}"
  echo ""
  echo "Top risques:"
  top_risks 10 | sed 's/\x1B\[[0-9;]*[A-Za-z]//g'
} > "$SUMMARY_TXT"

exit 0
