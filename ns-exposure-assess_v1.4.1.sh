#!/bin/sh
# =============================================================================
#  ns-exposure-assess.sh
#  NetScaler ADC / Gateway exposure, upgrade-readiness and compromise assessor
#  Bulletin coverage: CTX697096 (CVE-2026-88771 .. CVE-2026-88778)
#
#  Author : BK Chaudhari, Technical Consultant (NetScaler ADC)
#  Version: 1.4.1 (30 Sep 2026) - help text aligned with the guide (Option A / B, bash)
#
#  READ-ONLY. The script changes no configuration, restarts nothing and
#  deletes nothing. It reads configuration, file metadata, process and
#  socket tables and logs, then writes a text report and a CSV of findings.
#
#  Provided as is, without warranty. It complements, and does not replace,
#  the NetScaler Console IoC scan or the IoC script supplied by Citrix
#  Support. A result without findings means "nothing found in the places
#  checked", not "not compromised".
#
#  USAGE (from the NetScaler shell, as nsroot) - always start it with bash:
#    Option A, this script alone:
#      bash ns-exposure-assess.sh -p <upgrade date YYYY-MM-DD>
#    Option B, this script + the Citrix IoC script from your support case:
#      bash ns-exposure-assess.sh -p <upgrade date> -v ioc-script-v3.sh
#
#  OPTIONS
#    -c <file>   Assess an exported ns.conf offline (configuration checks only)
#    -b <build>  Build as shown by "show ns version", e.g. 14.1-73.37
#                (default: read from the ns.conf header)
#    -f          Build is a FIPS or NDcPP edition
#    -i <state>  Live Enhanced ISN state: ENABLED or DISABLED
#                (default: read from the saved configuration)
#    -p <date>   Date the fixed build was installed, YYYY-MM-DD
#                (used to judge log coverage of the exposure window)
#    -k <file>   Indicator file with extra indicators to hunt for (see below)
#    -v <file>   Vendor IoC script from Citrix Support: run it unmodified and
#                import its results into this report (not bundled; supply your own)
#    -o <dir>    Output directory (default: /var/tmp)
#    -h          Help
#
#  INDICATOR FILE (-k) - one indicator per line, "type:value":
#    ip:203.0.113.10           searched in HTTP access logs
#    sha256:<64 hex chars>     compared with files in web, temp and config paths
#    path:/var/tmp/example     reported if the path exists
#    text:some-string          searched in HTTP, ns and shell logs
#  Lines starting with # are ignored. Use indicators from Citrix Support,
#  NetScaler Console, your CERT or your own incident response.
#
#  VENDOR SCRIPT (-v): this script never contains vendor indicators. It runs
#  the file you supply, keeps its results.txt as evidence, and converts each
#  "matched" entry into a finding (NSA-V01..). Log-only matches are REVIEW.
#
#  EXIT CODES
#    0  no findings above INFO
#    1  REVIEW items only
#    2  exposure: build below the fixed build, or an open configuration action
#    3  HIGH or CRITICAL compromise indicators
#    4  could not determine the build or read the configuration
# =============================================================================

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077
LC_ALL=C
export LC_ALL

SCRIPT_VERSION="1.4.1"
CONF=/nsconfig/ns.conf
OFFLINE=0
BUILD_ARG=""
FIPS=0
ISN_ARG=""
PATCH_DATE=""
IOC_FILE=""
VENDOR=""
OUT_DIR=/var/tmp

usage() { sed -n '2,60p' "$0" | sed 's/^#//'; exit 0; }

while getopts "c:b:fi:p:k:v:o:h" opt; do
    case "$opt" in
        c) CONF="$OPTARG"; OFFLINE=1 ;;
        b) BUILD_ARG="$OPTARG" ;;
        f) FIPS=1 ;;
        i) ISN_ARG=$(printf '%s' "$OPTARG" | tr 'a-z' 'A-Z') ;;
        p) PATCH_DATE="$OPTARG" ;;
        k) IOC_FILE="$OPTARG" ;;
        v) VENDOR="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        h|*) usage ;;
    esac
done

HOST=$(hostname 2>/dev/null || echo unknown)
STAMP=$(date '+%Y%m%d_%H%M%S' 2>/dev/null || echo now)
REPORT="$OUT_DIR/nsassess_${HOST}_${STAMP}.txt"
CSV="$OUT_DIR/nsassess_${HOST}_${STAMP}.csv"
WORK=$(mktemp -d "${OUT_DIR}/nsassess.XXXXXX" 2>/dev/null) || WORK="$OUT_DIR/nsassess.$$"
mkdir -p "$WORK" 2>/dev/null

N_CRIT=0; N_HIGH=0; N_EXPO=0; N_REV=0; N_INFO=0; N_PASS=0

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
say()  { printf '%s\n' "$*" >> "$REPORT"; }
rule() { say "--------------------------------------------------------------------------"; }
head1() { say ""; say "=========================================================================="; say " $1"; say "=========================================================================="; printf '[nsassess] %s\n' "$1" >&2; }
head2() { say ""; say "## $1"; }

csv_field() { printf '"%s"' "$(printf '%s' "$1" | tr '\n' ' ' | sed 's/"/""/g')"; }

# finding SEVERITY ID "Title" "Evidence (may be multi-line)" "Action"
# SEVERITY: CRITICAL | HIGH | EXPOSURE | REVIEW | INFO | PASS
finding() {
    sev=$1; fid=$2; title=$3; evid=$4; act=$5
    case "$sev" in
        CRITICAL) N_CRIT=$((N_CRIT+1)) ;;
        HIGH)     N_HIGH=$((N_HIGH+1)) ;;
        EXPOSURE) N_EXPO=$((N_EXPO+1)) ;;
        REVIEW)   N_REV=$((N_REV+1)) ;;
        INFO)     N_INFO=$((N_INFO+1)) ;;
        PASS)     N_PASS=$((N_PASS+1)) ;;
    esac
    say ""
    say "[$sev] $fid  $title"
    if [ -n "$evid" ]; then
        printf '%s\n' "$evid" | head -40 | sed 's/^/      | /' >> "$REPORT"
        cnt=$(printf '%s\n' "$evid" | wc -l | tr -d ' ')
        [ "$cnt" -gt 40 ] && say "      | ... $((cnt-40)) more line(s) in the evidence set"
    fi
    [ -n "$act" ] && say "      > Action: $act"
    { csv_field "$HOST"; printf ','; csv_field "$sev"; printf ','; csv_field "$fid"; printf ',';
      csv_field "$title"; printf ','; csv_field "$(printf '%s\n' "$evid" | head -5)"; printf ',';
      csv_field "$act"; printf '\n'; } >> "$CSV"
}

have() { command -v "$1" >/dev/null 2>&1; }

# grep configuration (case-insensitive, extended); prints matching lines
cfg() { grep -E -i -- "$1" "$2" 2>/dev/null; }

# sha256 of a file, lower-case hex, works on BSD and Linux
file_sha256() {
    if have sha256; then sha256 -q "$1" 2>/dev/null
    elif have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif have openssl; then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    fi
}

# read gzip or plain log
readlog() { case "$1" in *.gz) gzip -dc "$1" 2>/dev/null ;; *) cat "$1" 2>/dev/null ;; esac; }

# numeric compare of builds "73.37" >= "73.32"
build_ge() {
    a1=${1%%.*}; a2=${1#*.}; b1=${2%%.*}; b2=${2#*.}
    [ "$a1" -gt "$b1" ] && return 0
    [ "$a1" -eq "$b1" ] && [ "$a2" -ge "$b2" ] && return 0
    return 1
}

# ----------------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------------
: > "$REPORT"
printf 'host,severity,id,title,evidence,action\n' > "$CSV"
printf '[nsassess] v%s started - report: %s\n' "$SCRIPT_VERSION" "$REPORT" >&2
if [ -z "$BASH_VERSION" ] && [ $OFFLINE -eq 0 ]; then
    printf '[nsassess] tip: start this script with bash (the appliance sh can crash on large configurations)\n' >&2
fi
if [ -n "$VENDOR" ]; then printf '[nsassess] mode: Option B (with vendor IoC script)\n' >&2; else printf '[nsassess] mode: Option A (this script alone)\n' >&2; fi
head1 "NetScaler exposure and compromise assessment  v$SCRIPT_VERSION"
say "Host        : $HOST"
say "Run at      : $(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)"
say "Mode        : $([ $OFFLINE -eq 1 ] && echo "offline configuration ($CONF)" || echo 'on-appliance')"
say "Report      : $REPORT"
say "Findings CSV: $CSV"
say "Nature      : read-only; no configuration change, restart or deletion"
say ""
say "Severity scale"
say "  CRITICAL  strong indicator of compromise - start incident response"
say "  HIGH      likely indicator of compromise - investigate before closing"
say "  EXPOSURE  vulnerable build or an open configuration action"
say "  REVIEW    needs human judgement or comparison with a clean baseline"
say "  INFO      context for the assessor"
say "  PASS      check ran and found nothing in the scope it covers"

if [ ! -r "$CONF" ]; then
    finding CRITICAL NSA-000 "Configuration not readable" "$CONF" "Run as nsroot from the shell, or pass an exported ns.conf with -c."
    say ""; say "Assessment stopped: no configuration."
    cat "$REPORT"; rm -rf "$WORK"; exit 4
fi

# ----------------------------------------------------------------------------
# 1. Build and bulletin status
# ----------------------------------------------------------------------------
head1 "1. Build and bulletin status (CTX697096)"

if [ -n "$BUILD_ARG" ]; then
    RAW_BUILD="$BUILD_ARG"
else
    RAW_BUILD=$(head -5 "$CONF" 2>/dev/null | sed -n 's/^#NS\([0-9][0-9]*\.[0-9][0-9]*\) Build \([0-9][0-9]*\.[0-9][0-9]*\).*/\1-\2/p' | head -1)
fi
printf '%s' "$RAW_BUILD" | grep -qiE 'fips|ndcpp' && FIPS=1
REL=$(printf '%s' "$RAW_BUILD" | sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\)[^0-9][^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
BLD=$(printf '%s' "$RAW_BUILD" | sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\)[^0-9][^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*/\2/p')
BUILD_STATE=UNKNOWN
FIXED=""

say "Detected build: ${RAW_BUILD:-unknown}  (release ${REL:-?}, build ${BLD:-?}, FIPS/NDcPP: $([ $FIPS -eq 1 ] && echo yes || echo no))"

if [ -z "$REL" ] || [ -z "$BLD" ]; then
    finding REVIEW NSA-B00 "Build could not be determined" "Header of $CONF did not contain '#NSx.y Build a.b'" "Re-run with -b and the value from 'show ns version'."
else
    case "$REL" in
        14.1) FIXED="73.37" ;;
        13.1) if [ "$FIPS" -eq 1 ] || [ "${BLD%%.*}" = "37" ]; then FIXED="37.279"; FIPS=1; else FIXED="64.23"; fi ;;
        *)    FIXED="EOL" ;;
    esac
    if [ "$FIXED" = "EOL" ]; then
        BUILD_STATE=VULNERABLE
        finding EXPOSURE NSA-B01 "Release $REL is end of life - no fix exists" "$RAW_BUILD" "Migrate to 14.1-73.37 or later. Treat an internet-facing EOL appliance as potentially compromised."
    elif build_ge "$BLD" "$FIXED"; then
        BUILD_STATE=FIXED
        finding PASS NSA-B01 "Build $REL-$BLD is at or above the fixed build $REL-$FIXED" "" ""
    else
        BUILD_STATE=VULNERABLE
        finding EXPOSURE NSA-B01 "Build $REL-$BLD is below the fixed build $REL-$FIXED" "CVE-2026-88771 and CVE-2026-88772 are exploited in the wild" "Preserve evidence, run the vendor IoC scan, then upgrade (13.1: prefer 64.24)."
    fi
    if [ "$REL" = "14.1" ] && [ "$BUILD_STATE" = "VULNERABLE" ] && ! build_ge "$BLD" "73.32"; then
        finding INFO NSA-B02 "Build also predates the August 2026 fixes (14.1-73.32)" "" "The upgrade to 73.37 covers both bulletins."
    fi
    if [ "$REL" = "13.1" ] && [ "$FIPS" -eq 0 ] && [ "$BUILD_STATE" = "VULNERABLE" ] && ! build_ge "$BLD" "63.21"; then
        finding INFO NSA-B02 "Build also predates the August 2026 fixes (13.1-63.21)" "" "The upgrade to 64.24 covers both bulletins."
    fi
    [ "$REL" = "13.1" ] && finding INFO NSA-B03 "13.1 reached End of Maintenance on 15 Sep 2026" "" "Plan the move to 14.1."
fi

# ----------------------------------------------------------------------------
# 2. CVE preconditions, per partition
# ----------------------------------------------------------------------------
head1 "2. CVE preconditions (default partition and each admin partition)"
if [ "$BUILD_STATE" = "FIXED" ]; then
    say "Build is fixed: matches below describe the pre-upgrade exposure window,"
    say "except CVE-2026-88778, which needs a configuration change on any build."
fi

PART_LIST="$CONF"
PDIR=$(dirname "$CONF")/partitions
if [ -d "$PDIR" ]; then
    for p in "$PDIR"/*/ns.conf; do [ -r "$p" ] && PART_LIST="$PART_LIST
$p"; done
fi

sev_for_precond() { [ "$BUILD_STATE" = "FIXED" ] && echo INFO || echo EXPOSURE; }

TCP_TYPES='HTTP|SSL|SSL_BRIDGE|TCP|SSL_TCP|FTP|NNTP|RTSP|RDP|DNS_TCP|DOT|SIP_TCP|SIP_SSL|DIAMETER|SSL_DIAMETER|MYSQL|MSSQL|ORACLE|SMPP|MQTT|MQTT_TLS|MONGO|MONGO_TLS|PROXY|SSL_PROXY|USER_TCP|USER_SSL_TCP'

for PC in $PART_LIST; do
    [ -r "$PC" ] || continue
    if [ "$PC" = "$CONF" ]; then PN=default; else PN=$(basename "$(dirname "$PC")"); fi
    head2 "Partition: $PN  ($PC)"
    SEV=$(sev_for_precond)

    printf '[nsassess]   partition %s: CVE-2026-88771\n' "$PN" >&2
    # 88771 - all deployments
    finding "$SEV" "NSA-C71[$PN]" "CVE-2026-88771 unauthenticated RCE applies to every deployment" "" "Fixed build is the only remedy."

    printf '[nsassess]   partition %s: CVE-2026-88772\n' "$PN" >&2
    # 88772 - DTLS
    v72=""
    vpn=$(cfg '^add vpn vserver ' "$PC")
    if [ -n "$vpn" ]; then
        v72=$(printf '%s\n' "$vpn" | grep -viE -- '-dtls[[:space:]]+OFF')
    fi
    dt=$(cfg '^add (lb|vpn|cs|gslb) vserver [^ ]+ DTLS( |$)' "$PC")
    [ -n "$dt" ] && v72=$(printf '%s\n%s' "$v72" "$dt" | sed '/^$/d')
    if [ -n "$v72" ]; then
        finding "$SEV" "NSA-C72[$PN]" "CVE-2026-88772 precondition met: DTLS enabled (VPN vServer without -dtls OFF, or DTLS vServer)" "$v72" "Fixed build. Interim only: set vpn vserver <name> -dtls OFF (EDT falls back to TCP; does not fix 88771)."
    else
        finding PASS "NSA-C72[$PN]" "CVE-2026-88772 precondition not met (no DTLS-enabled vServers)" "" ""
    fi

    printf '[nsassess]   partition %s: CVE-2026-88773\n' "$PN" >&2
    # 88773 - HTTP / SSL vservers
    v73=$(cfg '^add (lb|cs|vpn|authentication) vserver [^ ]+ (HTTP|SSL)( |$)' "$PC")
    if [ -n "$v73" ]; then
        finding "$SEV" "NSA-C73[$PN]" "CVE-2026-88773 precondition met: HTTP/SSL LB, CS, VPN or AAA vServers ($(printf '%s\n' "$v73" | wc -l | tr -d ' '))" "$v73" "Fixed build; apply strict HTTP validation (dropInvalReqs) as defence in depth."
    else
        finding PASS "NSA-C73[$PN]" "CVE-2026-88773 precondition not met" "" ""
    fi

    printf '[nsassess]   partition %s: CVE-2026-88774\n' "$PN" >&2
    # 88774 - URL based expressions in policies
    v74=$(cfg '^(add|set) .*HTTP\.REQ\.URL' "$PC" | sort -u)
    if [ -n "$v74" ]; then
        finding "$SEV" "NSA-C74[$PN]" "CVE-2026-88774 precondition met: policies with HTTP URL expressions ($(printf '%s\n' "$v74" | wc -l | tr -d ' '))" "$v74" "Fixed build; review security-relevant URL policies (responder blocks, authorization) for bypass exposure."
    else
        finding PASS "NSA-C74[$PN]" "CVE-2026-88774 precondition not found (no HTTP.REQ.URL expressions)" "" ""
    fi

    printf '[nsassess]   partition %s: CVE-2026-88775\n' "$PN" >&2
    # 88775 - Gateway or AAA vserver
    v75=$(cfg '^add (vpn|authentication) vserver ' "$PC")
    if [ -n "$v75" ]; then
        finding "$SEV" "NSA-C75[$PN]" "CVE-2026-88775 precondition met: Gateway or AAA vServers" "$v75" "Fixed build."
    else
        finding PASS "NSA-C75[$PN]" "CVE-2026-88775 precondition not met" "" ""
    fi

    printf '[nsassess]   partition %s: CVE-2026-88776\n' "$PN" >&2
    # 88776 - ORACLE LB
    v76=$(cfg '^add lb vserver [^ ]+ ORACLE( |$)' "$PC")
    if [ -n "$v76" ]; then
        finding "$SEV" "NSA-C76[$PN]" "CVE-2026-88776 precondition met: ORACLE LB vServers" "$v76" "Fixed build."
    else
        finding PASS "NSA-C76[$PN]" "CVE-2026-88776 precondition not met" "" ""
    fi

    printf '[nsassess]   partition %s: CVE-2026-88777\n' "$PN" >&2
    # 88777 - non-HTTP L7: FTP, LSN ALG, RTSP, DNS64, NAT64
    v77=$(cfg '^add (lb|cs) vserver [^ ]+ FTP( |$)|^add service [^ ]+ [^ ]+ FTP( |$)|^add servicegroup [^ ]+ FTP( |$)|^add lb monitor [^ ]+ FTP(-EXTENDED)?( |$)|^set lsn group .*-rtspalg ENABLED|^add lb vserver .* DNS .*-dns64 ENABLED|^add dns policy64 |^add nat64 ' "$PC")
    lsn=$(cfg '^add lsn group ' "$PC" | awk '{print $4}')
    for g in $lsn; do
        if ! cfg "^set lsn group $g .*-ftp DISABLED" "$PC" >/dev/null; then
            v77=$(printf '%s\nadd lsn group %s  (FTP ALG enabled by default - no -ftp DISABLED found)' "$v77" "$g" | sed '/^$/d')
        fi
    done
    if [ -n "$v77" ]; then
        finding "$SEV" "NSA-C77[$PN]" "CVE-2026-88777 precondition met: non-HTTP Layer 7 features" "$v77" "Fixed build; disable unused FTP/RTSP ALGs on LSN groups."
    else
        finding PASS "NSA-C77[$PN]" "CVE-2026-88777 precondition not met" "" ""
    fi

    printf '[nsassess]   partition %s: CVE-2026-88778\n' "$PN" >&2
    # 88778 - TCP vservers + Enhanced ISN
    v78=$(cfg "^add (lb|cs|vpn|authentication|gslb|cr) vserver [^ ]+ ($TCP_TYPES)( |\$)" "$PC")
    if cfg '^set ns tcpParam .*-enhancedISNgeneration ENABLED' "$PC" >/dev/null; then ISN_CFG=ENABLED; else ISN_CFG=DISABLED; fi
    ISN_USE=$ISN_CFG
    [ "$PN" = "default" ] && [ -n "$ISN_ARG" ] && ISN_USE=$ISN_ARG
    if [ -n "$v78" ] && [ "$ISN_USE" != "ENABLED" ]; then
        finding EXPOSURE "NSA-C78[$PN]" "CVE-2026-88778 open: TCP-based vServers and Enhanced ISN Generation $ISN_USE (saved config: $ISN_CFG)" "$(printf '%s\n' "$v78" | head -10)" "set ns tcpParam -enhancedISNgeneration ENABLED in this partition, then save ns config. Required even on a fixed build."
    elif [ -n "$v78" ]; then
        finding PASS "NSA-C78[$PN]" "CVE-2026-88778 mitigated: Enhanced ISN Generation ENABLED" "" ""
    else
        finding PASS "NSA-C78[$PN]" "CVE-2026-88778 precondition not met (no TCP-based vServers)" "" ""
    fi
done
# the subshell above cannot update counters; recount from the CSV
recount() {
    N_CRIT=$(grep -c '^"[^"]*","CRITICAL"' "$CSV"); N_HIGH=$(grep -c '^"[^"]*","HIGH"' "$CSV")
    N_EXPO=$(grep -c '^"[^"]*","EXPOSURE"' "$CSV"); N_REV=$(grep -c '^"[^"]*","REVIEW"' "$CSV")
    N_INFO=$(grep -c '^"[^"]*","INFO"' "$CSV"); N_PASS=$(grep -c '^"[^"]*","PASS"' "$CSV")
}

# ----------------------------------------------------------------------------
# 3. Upgrade readiness and known issues
# ----------------------------------------------------------------------------
head1 "3. Upgrade readiness and known issues"

vars=$(cfg '^add ns variable ' "$CONF")
if [ -n "$vars" ] && [ "$REL" = "13.1" ]; then
    finding EXPOSURE NSA-U01 "NetScaler variables configured: 13.1-64.23 can enter a cyclic reboot during upgrade" "$vars" "Upgrade directly to 13.1-64.24."
elif [ -n "$vars" ]; then
    finding INFO NSA-U01 "NetScaler variables configured" "$vars" "Relevant only for 13.1 upgrades (use 64.24)."
else
    finding PASS NSA-U01 "No NetScaler variables (13.1-64.23 reboot-loop issue not applicable)" "" ""
fi

saml=$(cfg '^add authentication samlAction .*-samlRejectUnsignedAssertion OFF|^set authentication samlAction .*-samlRejectUnsignedAssertion OFF' "$CONF" | awk '{print $1" "$2" "$3" "$4}')
if [ -n "$saml" ]; then
    finding EXPOSURE NSA-U02 "SAML actions accept unsigned assertions; the fixed builds enforce signed assertions" "$saml" "Configure the IdP to sign assertions before upgrading; test SAML logon after upgrading."
else
    finding PASS NSA-U02 "No SAML action accepts unsigned assertions" "" ""
fi

if [ $OFFLINE -eq 0 ]; then
    if [ -f /nsconfig/httpd.conf ]; then
        finding REVIEW NSA-U03 "Persistent web server override /nsconfig/httpd.conf present" "$(ls -l /nsconfig/httpd.conf 2>/dev/null)" "An old copy overrides the new build's config after upgrade and can break Gateway pages. Rebase or remove it, and review its content for tampering."
    else
        finding PASS NSA-U03 "No persistent httpd.conf override in /nsconfig" "" ""
    fi
    varfree=$(df -k /var 2>/dev/null | awk 'NR==2{print $4}')
    varpct=$(df -k /var 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
    if [ -n "$varfree" ] && [ "$varfree" -lt 4194304 ]; then
        finding REVIEW NSA-U04 "Less than 4 GB free on /var ($varpct% used)" "$(df -h /var 2>/dev/null)" "Move evidence bundles and old builds off the appliance before installns; a full /var can leave logon pages missing after upgrade."
    else
        finding PASS NSA-U04 "Free space on /var adequate for an upgrade (${varpct:-?}% used)" "" ""
    fi
fi

if [ -d "$PDIR" ] && ls "$PDIR"/*/ns.conf >/dev/null 2>&1; then
    finding INFO NSA-U05 "Admin partitions present: Enhanced ISN Generation must be set in each one" "$(ls -d "$PDIR"/*/ 2>/dev/null)" "NetScaler Console IoC results may list partitions separately; the scan still covers the whole appliance."
fi

ha=$(cfg '^add HA node ' "$CONF")
[ -n "$ha" ] && finding INFO NSA-U06 "High availability configured" "$ha" "Run this assessment on both nodes; upgrade secondary first, fail over, then upgrade the former primary."

# ----------------------------------------------------------------------------
# 4. Configuration tampering indicators (config-only, works offline)
# ----------------------------------------------------------------------------
head1 "4. Configuration tampering indicators"

users=$(cfg '^add system user ' "$CONF" | awk '{print $4}' | sort -u)
supers=$(cfg '^bind system user [^ ]+ superuser' "$CONF" | awk '{print $4}' | sort -u)
if [ -n "$users" ]; then
    finding REVIEW NSA-G01 "Local system users - confirm each one is known and approved" "$(printf 'users: %s\nsuperuser bindings: %s' "$(echo $users)" "$(echo $supers)")" "Remove unknown accounts only after preserving evidence; unknown superusers indicate compromise."
else
    finding PASS NSA-G01 "No local system users besides nsroot" "" ""
fi

inj=$(cfg '^add (rewrite|responder) action .*(<script|javascript:|document\.cookie|atob\(|eval\(|https?://[^ "]*\.(ru|cn|top|xyz|zip|click))' "$CONF" | cut -c1-300)
if [ -n "$inj" ]; then
    finding HIGH NSA-G02 "Rewrite/responder actions that inject script or reference external hosts" "$inj" "Check whether these are approved. Script injection into logon pages is a credential-harvesting technique."
else
    finding PASS NSA-G02 "No script-injecting rewrite or responder actions found" "" ""
fi

sshkeys=$(cfg '^add system sshkey |^add ssh key' "$CONF")
[ -n "$sshkeys" ] && finding REVIEW NSA-G03 "SSH keys defined in configuration" "$sshkeys" "Confirm each key belongs to an approved administrator."

mgmt=$(cfg '^(add|set) ns ip [^ ]+ .*-mgmtAccess ENABLED' "$CONF" | grep -vi -- '-type NSIP')
[ -n "$mgmt" ] && finding REVIEW NSA-G04 "Management access enabled on non-NSIP addresses" "$mgmt" "Disable management access on SNIPs that are not management interfaces."

gui=$(cfg '^set ns ip .*-gui SECUREONLY' "$CONF")
[ -z "$gui" ] && [ $OFFLINE -eq 0 ] && finding REVIEW NSA-G05 "Management GUI may allow HTTP (no -gui SECUREONLY found in saved config)" "" "Verify with show ns ip <NSIP>; if GUI is ENABLED, set ns ip <NSIP> -gui SECUREONLY on each node."

if [ $OFFLINE -eq 1 ]; then
    head1 "Offline mode: host, file, process and log checks skipped"
    recount
else

# ----------------------------------------------------------------------------
# 5. File system indicators
# ----------------------------------------------------------------------------
head1 "5. File system indicators"

WEBROOTS="/var/netscaler/logon /var/netscaler/gui /netscaler/ns_gui /netscaler/portal /var/vpn /var/netscaler/websocketd"
EXISTING=""
for d in $WEBROOTS; do [ -d "$d" ] && EXISTING="$EXISTING $d"; done

# reference time: newest firmware install directory
REF="$WORK/ref_install"
newest=$(ls -td /var/nsinstall/*/ 2>/dev/null | head -1)
if [ -n "$newest" ]; then
    touch -r "$newest" "$REF" 2>/dev/null
    say "Reference for 'new' files: firmware install directory $newest ($(ls -ld "$newest" | awk '{print $6" "$7" "$8}'))"
fi

# 5.1 executable content in web roots, excluding vendor trees
NEWER=""; [ -f "$REF" ] && NEWER="-newer $REF"
scripts=$(find $EXISTING -type f $NEWER \( -iname '*.php' -o -iname '*.xhtml' -o -iname '*.phtml' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.sh' -o -iname '*.cgi' -o -iname '*.jsp' \) \
    ! -path '*/admin_ui/*' ! -path '*/websocketd/*' 2>/dev/null)
allscripts=$(find $EXISTING -type f \( -iname '*.php' -o -iname '*.xhtml' -o -iname '*.phtml' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.sh' -o -iname '*.cgi' -o -iname '*.jsp' \) ! -path '*/admin_ui/*' ! -path '*/websocketd/*' 2>/dev/null)
hot=""
for f in $allscripts; do
    if grep -Eq 'eval[[:space:]]*\(|assert[[:space:]]*\(|passthru|shell_exec|pcntl_exec|gzinflate|str_rot13|\$_(POST|GET|REQUEST|COOKIE)\[' "$f" 2>/dev/null && grep -Eq '<\?(php|=)?' "$f" 2>/dev/null; then
        hot="$hot
$(ls -l "$f")"
    fi
done
hot=$(printf '%s' "$hot" | sed '/^$/d')
[ -n "$hot" ] && finding CRITICAL NSA-F01 "PHP files in web-served paths combining request input with code-execution functions" "$hot" "Do not delete. Hash and copy off-box, isolate the appliance and start incident response."
if [ -n "$scripts" ]; then
    finding REVIEW NSA-F02 "Script files in web-served paths outside vendor trees, newer than the firmware install ($(printf '%s\n' "$scripts" | wc -l | tr -d ' '))" "$(for f in $scripts; do ls -l "$f"; done)" "Compare with a clean appliance on the same build; unexpected files are suspicious."
else
    finding PASS NSA-F02 "No script files added to web-served paths since the firmware install" "" ""
fi

# 5.2 vendor trees: files newer than the install
if [ -f "$REF" ]; then
    vnew=$(find /netscaler/ns_gui/admin_ui /var/netscaler/gui/admin_ui /var/netscaler/websocketd /var/netscaler/gui/websocketd -type f -newer "$REF" 2>/dev/null | head -50)
    [ -n "$vnew" ] && finding HIGH NSA-F03 "Files in vendor PHP trees modified after the firmware install" "$(for f in $vnew; do ls -l "$f"; done)" "Vendor trees should match the install. Compare hashes with a clean same-build appliance."
    wnew=$(find $EXISTING -type f -newer "$REF" ! -path '*/admin_ui/*' ! -path '*/websocketd/*' 2>/dev/null | head -60)
    if [ -n "$wnew" ]; then
        finding REVIEW NSA-F04 "Web-served files changed after the firmware install" "$(for f in $wnew; do ls -l "$f"; done)" "Expected only for approved portal themes or customisations."
    else
        finding PASS NSA-F04 "No web-served files changed after the firmware install" "" ""
    fi
fi

# 5.3 hidden entries and ELF binaries in web roots / temp
hidden=$(find $EXISTING -name '.*' ! -name '.' ! -name '..' ! -name '.htaccess' 2>/dev/null | head -50)
[ -n "$hidden" ] && finding HIGH NSA-F05 "Hidden files or directories in web-served paths" "$hidden" "Hidden entries in web roots are a common way to conceal web shells. Preserve and investigate."
elf=""
for f in $(find $EXISTING /var/tmp /tmp -type f -size +1k -size -50000k ! -path '/var/tmp/support/*' ! -name '*.tgz' ! -name '*.gz' 2>/dev/null | head -500); do
    magic=$(dd if="$f" bs=4 count=1 2>/dev/null | od -An -c 2>/dev/null | tr -d ' \n')
    [ "$magic" = '177ELF' ] && elf="$elf
$(ls -l "$f")"
done
elf=$(printf '%s' "$elf" | sed '/^$/d')
[ -n "$elf" ] && finding HIGH NSA-F06 "ELF binaries in web-served or temporary paths" "$elf" "Binaries do not belong there. Hash, copy off-box and analyse."
[ -z "$hidden" ] && [ -z "$elf" ] && finding PASS NSA-F05 "No hidden entries or ELF binaries in web-served and temp paths" "" ""

# 5.4 setuid / setgid
shells=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \( -name 'sh' -o -name 'bash' -o -name 'csh' -o -name 'tcsh' -o -name 'ksh' -o -name 'zsh' -o -name 'python*' -o -name 'perl*' -o -name 'php*' \) 2>/dev/null)
tmpsuid=$(find /var/tmp /tmp /var/netscaler /var/vpn /flash -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
if [ -n "$shells" ] || [ -n "$tmpsuid" ]; then
    finding CRITICAL NSA-F07 "setuid/setgid shells or interpreters, or setuid files in writable paths" "$(for f in $shells $tmpsuid; do ls -l "$f"; done)" "A setuid shell is a root backdoor. Preserve evidence, isolate and rebuild."
else
    finding PASS NSA-F07 "No setuid shells/interpreters and no setuid files in writable paths" "" ""
fi

# 5.5 crash dumps
cores=$(find /var/core /var/crash -type f ! -name bounds ! -name 'sh-*' -mtime -30 2>/dev/null | head -30)
if [ -n "$cores" ]; then
    finding REVIEW NSA-F08 "Crash dumps in the last 30 days ($(printf '%s\n' "$cores" | wc -l | tr -d ' '))" "$(for f in $cores; do ls -l "$f"; done)" "Copy off-box before cleanup; memory-corruption exploits often crash the packet engine. Correlate with log timestamps."
else
    finding PASS NSA-F08 "No crash dumps in the last 30 days" "" ""
fi

# ----------------------------------------------------------------------------
# 6. Persistence
# ----------------------------------------------------------------------------
head1 "6. Persistence mechanisms"

for s in /nsconfig/rc.netscaler /flash/nsconfig/rc.netscaler /nsconfig/nsbefore.sh /nsconfig/nsafter.sh /flash/nsconfig/nsbefore.sh /flash/nsconfig/nsafter.sh; do
    [ -f "$s" ] || continue
    body=$(grep -Ev '^[[:space:]]*(#|$)' "$s" 2>/dev/null)
    [ -z "$body" ] && continue
    bad=$(printf '%s\n' "$body" | grep -Ei 'curl|wget|fetch |nc |ncat|socat|python|perl|php|base64|openssl|/tmp/|/var/tmp/|chmod [0-7]*[4-7][0-7][0-7][0-7]|chmod .*\+s|cp .* /netscaler|>> */etc/|/dev/tcp')
    if [ -n "$bad" ]; then
        finding HIGH NSA-P01 "Startup script $s contains download, interpreter or permission commands" "$bad" "Startup scripts run at every boot. Preserve and compare with approved changes."
    else
        finding REVIEW NSA-P02 "Startup script $s has active lines" "$body" "Confirm each line is an approved customisation."
    fi
done

cronout=""
for c in /etc/crontab /var/cron/tabs/* /nsconfig/crontab* /flash/nsconfig/crontab*; do
    [ -f "$c" ] || continue
    x=$(grep -Ev '^[[:space:]]*(#|$)' "$c" 2>/dev/null | grep -Ev 'lockf .* /netscaler/|/var/python/bin/python /netscaler/|curl http://(localhost|127\.0\.0\.1)' | grep -Ei 'https?://|wget|fetch |nc |ncat|socat|base64|/tmp/[^.]|/var/tmp/|/var/vpn|/var/netscaler/logon|sh -c|python|perl|php')
    [ -n "$x" ] && cronout="$cronout
== $c
$x"
done
cronout=$(printf '%s' "$cronout" | sed '/^$/d')
if [ -n "$cronout" ]; then
    finding HIGH NSA-P03 "Scheduled jobs running downloads, interpreters or files from temp/web paths" "$cronout" "Preserve and investigate; not part of a stock appliance."
else
    finding PASS NSA-P03 "No suspicious scheduled jobs" "" ""
fi

keys=""
for k in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /nsconfig/ssh/authorized_keys /flash/nsconfig/ssh/authorized_keys /var/nstmp/*/.ssh/authorized_keys; do
    [ -s "$k" ] && keys="$keys
$(ls -l "$k")
$(awk '{print "   key: "$1" ... "$NF}' "$k" 2>/dev/null)"
done
keys=$(printf '%s' "$keys" | sed '/^$/d')
[ -n "$keys" ] && finding REVIEW NSA-P04 "SSH authorized keys present" "$keys" "Confirm every key is owned by an approved administrator."

shells_pw=$(awk -F: '$1 !~ /^#/ && NF>=7 && $7 !~ /(nologin|false)$/ && $1 !~ /^(root|nsroot|toor|nsppe|uucp)$/ {print $1" -> "$7}' /etc/passwd 2>/dev/null)
[ -n "$shells_pw" ] && finding REVIEW NSA-P05 "OS accounts with an interactive shell" "$shells_pw" "Compare with a clean appliance on the same build."

for h in /etc/httpd.conf /nsconfig/httpd.conf; do
    [ -r "$h" ] || continue
    hx=$(grep -Ein '^[[:space:]]*(ScriptAlias|Alias|AliasMatch)[[:space:]].*(/tmp|/var/tmp|/var/vpn/[^t]|/var/core|/nsconfig|/flash)|^[[:space:]]*(AddHandler|AddType|SetHandler)[[:space:]].*(php|cgi-script).*\.(xhtml|html|htm|js|css|png|gif|jpg|ico|txt)' "$h" 2>/dev/null)
    if [ -n "$hx" ]; then
        finding HIGH NSA-P06 "Web server directives mapping code execution to unusual paths or extensions in $h" "$hx" "Compare with the same build's stock file; this is a known way to hide web shells."
    fi
done

# ----------------------------------------------------------------------------
# 7. Runtime: processes and network
# ----------------------------------------------------------------------------
head1 "7. Runtime state (processes and sockets)"

pl=$(ps -axww -o user,pid,ppid,command 2>/dev/null || ps auxww 2>/dev/null)
webproc=$(printf '%s\n' "$pl" | awk '$1=="nobody" || $1=="www" || $1=="daemon"' | grep -Ev '/bin/httpd|/usr/sbin/nshttpd|httpd -|awk ')
if [ -n "$webproc" ]; then
    finding CRITICAL NSA-R01 "Processes other than httpd running as the web server account" "$webproc" "Likely live attacker activity. Capture ps/sockstat output, isolate inbound and outbound, start incident response."
else
    finding PASS NSA-R01 "Only httpd runs under the web server account" "" ""
fi

tools=$(printf '%s\n' "$pl" | grep -Ei '(^|[ /])(nc|ncat|socat|curl|wget|fetch|python[0-9.]*|perl|php)( |$)|/dev/tcp|bash -i|sh -i' | grep -Ev 'grep|nsassess|ns-exposure-assess|/netscaler/|/usr/local/bin/python.*nscli|pitboss|monit')
[ -n "$tools" ] && finding REVIEW NSA-R02 "Download tools or interpreters running" "$tools" "Confirm each process is expected (some NetScaler services use Python or Perl)."

if have sockstat; then
    socks=$(sockstat -46 2>/dev/null)
elif have netstat; then
    socks=$(netstat -an 2>/dev/null)
fi
if [ -n "$socks" ]; then
    susp=$(printf '%s\n' "$socks" | awk 'tolower($2) ~ /^(sh|bash|csh|tcsh|ksh|nc|ncat|socat|python.*|perl|php.*|curl|wget)$/ && $6 !~ /^(127\.|\[?::1)/ && $6 !~ /^\*:/')
    if [ -n "$susp" ]; then
        finding CRITICAL NSA-R03 "Network sockets owned by shells, interpreters or download tools" "$susp" "Probable reverse shell or C2 channel. Block the remote address upstream and isolate."
    else
        finding PASS NSA-R03 "No shells or interpreters with non-loopback sockets (loopback-only stock services ignored)" "" ""
    fi
fi

# ----------------------------------------------------------------------------
# 8. Logs
# ----------------------------------------------------------------------------
head1 "8. Log evidence and coverage"

ACC=$(ls /var/log/httpaccess*.log* /var/log/httpaccess* 2>/dev/null | sort -u)
ERR=$(ls /var/log/httperror* 2>/dev/null | sort -u)
NSL=$(ls /var/log/ns.log* 2>/dev/null | sort -u)
SHL=$(ls /var/log/sh.log* /var/log/bash.log* 2>/dev/null | sort -u)

# coverage
oldest=$(ls -tr $ACC $NSL 2>/dev/null | head -1)
if [ -n "$oldest" ]; then
    say "Oldest retained log: $oldest ($(ls -l "$oldest" | awk '{print $6" "$7" "$8}'))"
    if [ -n "$PATCH_DATE" ]; then
        pd=$(printf '%s' "$PATCH_DATE" | tr -d '-')
        if touch -t "${pd}0000" "$WORK/pd" 2>/dev/null; then
            if [ "$oldest" -ot "$WORK/pd" ]; then
                finding INFO NSA-L00 "Retained logs reach back before the patch date $PATCH_DATE" "" "Log checks below cover part of the exposure window; check for gaps."
            else
                finding REVIEW NSA-L00 "No retained logs older than the patch date $PATCH_DATE" "" "The exposure window is not covered on-box. Use SIEM/syslog copies or state the visibility gap in the report."
            fi
        fi
    fi
else
    finding REVIEW NSA-L00 "No HTTP access or ns.log files found" "" "Log-based checks have no coverage."
fi

# 8.1 successful requests for executable content outside vendor paths
if [ -n "$ACC" ]; then
    hits=""
    for f in $ACC; do
        h=$(readlog "$f" | grep -Ei '"(GET|POST|PUT) [^ ]*\.(php|phtml|xhtml|pl|py|sh|cgi|jsp)(\?[^ ]*)? HTTP/[0-9.]+" 20[0-9] ' | grep -Evi '/admin_ui/|/websocketd/|/menu/|/nitro/' | tail -20)
        [ -n "$h" ] && hits="$hits
== $f
$h"
    done
    hits=$(printf '%s' "$hits" | sed '/^$/d')
    if [ -n "$hits" ]; then
        finding HIGH NSA-L01 "Successful requests (2xx) for script files outside vendor paths" "$hits" "A 2xx on an unexpected script means it exists and ran. Find the file and the source IPs."
    else
        finding PASS NSA-L01 "No successful requests for unexpected script files" "" ""
    fi

    mth=""
    for f in $ACC; do
        m=$(readlog "$f" | grep -E '"(PUT|DELETE|PROPFIND|MKCOL|TRACE|CONNECT) ' | tail -10)
        [ -n "$m" ] && mth="$mth
== $f
$m"
    done
    mth=$(printf '%s' "$mth" | sed '/^$/d')
    [ -n "$mth" ] && finding REVIEW NSA-L02 "Unusual HTTP methods against the appliance" "$mth" "Not used by Gateway clients; review source IPs and response codes."

    trav=""
    for f in $ACC; do
        t=$(readlog "$f" | grep -Ei '(\.\./|%2e%2e|%252e|%00|%0a|%0d)[^ ]* HTTP/[0-9.]+" 20[0-9]' | tail -10)
        [ -n "$t" ] && trav="$trav
== $f
$t"
    done
    trav=$(printf '%s' "$trav" | sed '/^$/d')
    [ -n "$trav" ] && finding HIGH NSA-L03 "Successful requests containing traversal or control-character encodings" "$trav" "Investigate each source; encoded traversal answered with 2xx is a strong exploitation signal."
fi

# 8.2 shell history: anti-forensics and credential access
if [ -n "$SHL" ]; then
    af=""
    for f in $SHL; do
        a=$(readlog "$f" | grep -E 'history -c|unset HISTFILE|HISTSIZE=0|HISTFILE=/dev/null|rm -[rf]* */var/log|> */var/log/|truncate .*var/log|rm .*/var/core|rm .*/var/nslog|shred ' | tail -10)
        [ -n "$a" ] && af="$af
== $f
$a"
    done
    af=$(printf '%s' "$af" | sed '/^$/d')
    if [ -n "$af" ]; then
        finding HIGH NSA-L04 "Commands that erase logs, history or crash dumps" "$af" "Anti-forensic activity. Rely on off-box logs and treat as suspected compromise."
    else
        finding PASS NSA-L04 "No log or history wiping commands in shell logs" "" ""
    fi
    ca=""
    for f in $SHL; do
        c=$(readlog "$f" | grep -Ei 'cat .*(ns\.conf|/nsconfig/ssl|\.key)|tar .*(/nsconfig|/flash)|scp .*(/nsconfig|/flash)|curl .*-T|curl .*--upload|/etc/master\.passwd' | tail -10)
        [ -n "$c" ] && ca="$ca
== $f
$c"
    done
    ca=$(printf '%s' "$ca" | sed '/^$/d')
    [ -n "$ca" ] && finding REVIEW NSA-L05 "Shell commands reading or exporting configuration, keys or password files" "$ca" "Confirm each was an approved administrator action (support bundles and backups are legitimate)."
fi

# 8.3 packet engine instability in ns.log
if [ -n "$NSL" ]; then
    pe=0
    for f in $NSL; do
        n=$(readlog "$f" | grep -Eci 'nsppe.*(core|crash|died|restart)|pe.*heartbeat.*miss')
        pe=$((pe + ${n:-0}))
    done
    if [ "$pe" -gt 0 ]; then
        finding REVIEW NSA-L06 "Packet engine crash or restart events in ns.log ($pe)" "" "Correlate timestamps with HTTP logs and crash dumps (NSA-F08)."
    else
        finding PASS NSA-L06 "No packet engine crash events in retained ns.log files" "" ""
    fi
fi


# ----------------------------------------------------------------------------
# 8b. Vendor IoC script (supplied by the operator, run unmodified)
# ----------------------------------------------------------------------------
if [ -n "$VENDOR" ]; then
    head1 "8b. Vendor IoC script ($VENDOR)"
    if [ ! -r "$VENDOR" ]; then
        finding REVIEW NSA-V00 "Vendor IoC script not readable" "$VENDOR" "Copy the script from your Citrix Support case to the appliance and pass its full path with -v."
    else
        VABS=$(cd "$(dirname "$VENDOR")" && pwd)/$(basename "$VENDOR")
        VSHA=$(file_sha256 "$VABS")
        VVER=$(grep -m1 -E 'IOC Scanner Script v[0-9]+' "$VABS" 2>/dev/null | sed 's/^[[:space:]]*//')
        VDATE=$(grep -m1 -E '^Date: ' "$VABS" 2>/dev/null)
        say "Vendor script : $VABS"
        say "Version       : ${VVER:-unknown}  ${VDATE}"
        say "SHA-256       : ${VSHA:-not computed}"
        VDIR="$WORK/vendor"; mkdir -p "$VDIR"
        if have bash; then VSH=bash; else VSH=sh; fi
        printf '[nsassess]   running vendor script with %s (this can take several minutes)\n' "$VSH" >&2
        ( cd "$VDIR" && $VSH "$VABS" > "$VDIR/stdout.txt" 2>&1 ); VRC=$?
        VRES="$VDIR/results.txt"
        if [ ! -s "$VRES" ]; then
            finding REVIEW NSA-V00 "Vendor script produced no results.txt (exit $VRC)" "$(tail -5 "$VDIR/stdout.txt" 2>/dev/null)" "Run it manually from its own folder and check the error."
        else
            KEEP="$OUT_DIR/vendor_results_${HOST}_${STAMP}.txt"
            cp "$VRES" "$KEEP" 2>/dev/null && chmod 600 "$KEEP" 2>/dev/null
            say "Vendor results kept as evidence: $KEEP"
            if ! grep -q '"results"' "$VRES"; then
                finding PASS NSA-V01 "Vendor IoC script: no matches (${VVER:-unknown})" "" "A vendor result without matches is one data point, not proof of a clean appliance."
            else
                # flatten the vendor JSON into NAME / MSG / PATH / END records
                awk '
                  function val(line,  v){ sub(/^[^:]*:[[:space:]]*"/,"",line); sub(/",?[[:space:]]*$/,"",line); return line }
                  /"ioc_name":/ { print "NAME\t" val($0) }
                  /"message":/  { print "MSG\t"  val($0) }
                  /"path":/     { print "PATH\t" val($0) }
                  /^  }/        { print "END" }
                ' "$VRES" > "$VDIR/flat.txt"
                vn=0; name=""; msg=""; path=""
                while IFS= read -r line; do
                    case "$line" in
                        NAME*) name=${line#NAME	} ;;
                        MSG*)  msg=${line#MSG	} ;;
                        PATH*) path=${line#PATH	} ;;
                        END)
                            vn=$((vn+1))
                            ev=$(printf '%s' "$path" | sed -e 's/\\\\n/\
/g' -e 's/\\n/\
/g' -e 's/<br\/>/\
/g' -e 's/^\[-\] //' | sed '/^[[:space:]]*$/d')
                            [ -z "$ev" ] && ev="$msg"
                            nonlog=$(printf '%s\n' "$ev" | grep -Ev '^/var/log/(httperror|httpaccess)' | sed '/^$/d')
                            if [ -z "$nonlog" ]; then
                                n404=$(printf '%s\n' "$ev" | grep -c 'File does not exist\|" 404 ')
                                finding REVIEW "NSA-V$(printf '%02d' $vn)" "Vendor IoC match in web logs only: $name" "$ev" "Log-only match. 'File does not exist' / 404 ($n404 line(s)) means the request failed and nothing was served. Identify the real client (access log User-Agent, Gateway session logs) and confirm no file exists on disk."
                            else
                                finding CRITICAL "NSA-V$(printf '%02d' $vn)" "Vendor IoC match: $name" "$ev" "Vendor indicator matched on the appliance. Preserve evidence, do not delete, open a Citrix Support case with the vendor results file, and start incident response."
                            fi
                            name=""; msg=""; path="" ;;
                    esac
                done < "$VDIR/flat.txt"
                recount
            fi
        fi
    fi
fi

# ----------------------------------------------------------------------------
# 9. Operator-supplied indicators
# ----------------------------------------------------------------------------
if [ -n "$IOC_FILE" ] && [ ! -r "$IOC_FILE" ]; then
    printf '[nsassess] indicator file %s not found - skipping section 9 (it is optional)\n' "$IOC_FILE" >&2
fi
if [ -n "$IOC_FILE" ]; then
    head1 "9. Operator-supplied indicators ($IOC_FILE)"
    if [ ! -r "$IOC_FILE" ]; then
        finding REVIEW NSA-K00 "Indicator file not readable" "$IOC_FILE" "Check the path."
    else
        nk=0; kh=""
        HASHSET=$(grep -Ei '^sha256:[0-9a-f]{64}' "$IOC_FILE" | cut -d: -f2 | tr 'A-F' 'a-f')
        if [ -n "$HASHSET" ]; then
            for f in $(find $EXISTING /var/tmp /tmp /nsconfig /flash/nsconfig -type f -size -20000k 2>/dev/null); do
                s=$(file_sha256 "$f")
                [ -n "$s" ] && printf '%s\n' "$HASHSET" | grep -qx "$s" && kh="$kh
hash match: $f ($s)"
            done
        fi
        while IFS= read -r line; do
            case "$line" in ''|\#*) continue ;; esac
            t=${line%%:*}; v=${line#*:}; nk=$((nk+1))
            case "$t" in
                ip)   for f in $ACC; do readlog "$f" | grep -F "$v" | head -3 | sed "s|^|ip $v in $f: |"; done > "$WORK/k" ; [ -s "$WORK/k" ] && kh="$kh
$(cat "$WORK/k")" ;;
                path) [ -e "$v" ] && kh="$kh
path present: $(ls -ld "$v")" ;;
                text) for f in $ACC $ERR $NSL $SHL; do readlog "$f" | grep -F -- "$v" | head -3 | sed "s|^|text in $f: |"; done > "$WORK/k"; [ -s "$WORK/k" ] && kh="$kh
$(cat "$WORK/k")" ;;
            esac
        done < "$IOC_FILE"
        kh=$(printf '%s' "$kh" | sed '/^$/d')
        if [ -n "$kh" ]; then
            finding CRITICAL NSA-K01 "Operator-supplied indicators matched" "$kh" "Treat as confirmed compromise unless the match is explained. Start incident response."
        else
            finding PASS NSA-K01 "No match for $nk supplied indicator(s)" "" ""
        fi
    fi
fi

finding INFO NSA-Z01 "Complementary checks this script does not replace" "NetScaler Console Security Advisory: CVE detection and IoC scan
IoC script from Citrix Support (run it with -v if not done in this report)
File Integrity Monitoring in NetScaler Console
Firewall / proxy / NetFlow review of traffic from NSIP and SNIPs" "Run them and record results alongside this report. Repeat on the HA peer."
recount
fi  # end of on-appliance section

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
head1 "Summary"
say "CRITICAL: $N_CRIT   HIGH: $N_HIGH   EXPOSURE: $N_EXPO   REVIEW: $N_REV   INFO: $N_INFO   PASS: $N_PASS"
say ""
if [ "$N_CRIT" -gt 0 ] || [ "$N_HIGH" -gt 0 ]; then
    VERDICT="COMPROMISE INDICATORS PRESENT - start incident response"; RC=3
elif [ "$N_EXPO" -gt 0 ]; then
    VERDICT="EXPOSED - vulnerable build or open configuration action"; RC=2
elif [ "$N_REV" -gt 0 ]; then
    VERDICT="REVIEW REQUIRED - no strong indicators; items need human judgement"; RC=1
else
    VERDICT="NO FINDINGS in the scope checked (not proof of a clean appliance)"; RC=0
fi
[ "$BUILD_STATE" = "UNKNOWN" ] && [ "$RC" -lt 2 ] && RC=4 && VERDICT="$VERDICT; build unknown"
say "VERDICT: $VERDICT"
say ""
say "Next steps"
case "$RC" in
    3) say "  1. Do not delete or clean anything. Copy the report, CSV and flagged files off-box."
       say "  2. Isolate inbound and outbound at the upstream firewall; open a Citrix Support case."
       say "  3. Rebuild from a clean image on the fixed build; rotate every secret the appliance held." ;;
    2) say "  1. Preserve evidence and run the vendor IoC scan before any change."
       say "  2. Upgrade to the fixed build; enable Enhanced ISN Generation in every partition."
       say "  3. Re-run this assessment after the upgrade on both HA nodes." ;;
    1) say "  1. Compare REVIEW items with a clean appliance on the same build."
       say "  2. Close each item with evidence, or escalate to incident response." ;;
    *) say "  1. Record the result and the log coverage it rests on; repeat on the HA peer." ;;
esac
rule
say "Report: $REPORT"
say "CSV   : $CSV"

rm -rf "$WORK" 2>/dev/null
cat "$REPORT"
exit $RC
