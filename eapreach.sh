#!/bin/bash

# eapreach - reach each & preach
# Reach each EAP packet. Discover configuration reality. Preach configuration compliance.
# It's a tshark based EAP packet analyzer with certificate analysis included.

# Copyright (c) 2025 BerziOnline
# SPDX-License-Identifier: MIT
# eapreach v1.1

# ═══════════════════════════════════════════════════════════════════════════════
# COLOR DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

RESET='\033[0m'
CYAN='\033[36m'
CYAN_BOLD='\033[1;36m'
GRAY='\033[90m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'

# ═══════════════════════════════════════════════════════════════════════════════
# TRANSLATION TABLES
# ═══════════════════════════════════════════════════════════════════════════════

# EAPOL Packet Types (IEEE 802.1X-2020)
declare -A EAPOL_TYPES=(
    [0]="EAP Packet"
    [1]="Start"
    [2]="Logoff"
    [3]="Key"
    [4]="ASF Alert"
    [5]="MKA"
)

# EAP Method Types (IANA: https://www.iana.org/assignments/eap-numbers)
declare -A EAP_TYPES=(
    [1]="Identity"
    [2]="Notification"
    [3]="Legacy Nak"
    [4]="MD5-Challenge"
    [5]="OTP"
    [6]="GTC"
    [13]="EAP-TLS"
    [17]="LEAP"
    [21]="EAP-TTLS"
    [25]="PEAP"
    [26]="MS-EAP-Auth"
    [29]="EAP-MSCHAPv2"
    [32]="EAP-POTP"
    [43]="EAP-FAST"
    [55]="TEAP"
)

# Methods without server authentication and without key derivation
declare -A EAP_WEAK_TYPES=(
    [4]=1   # MD5-Challenge
    [5]=1   # OTP
    [6]=1   # GTC
    [17]=1  # LEAP
)

# EAP Codes (RFC 3748)
declare -A EAP_CODES=(
    [1]="Request"
    [2]="Response"
    [3]="Success"
    [4]="Failure"
)

# TLS Handshake Types (IANA TLS HandshakeType)
declare -A TLS_TYPES=(
    [1]="Client Hello"
    [2]="Server Hello"
    [4]="New Session Ticket"
    [11]="Certificate"
    [12]="Server Key Exchange"
    [13]="Certificate Request"
    [14]="Server Hello Done"
    [15]="Certificate Verify"
    [16]="Client Key Exchange"
    [20]="Finished"
    [22]="Certificate Status"
)

WEAK_CIPHER_PATTERN='_RC4_|_DES_|_3DES_|_NULL_|_EXPORT|_anon_'
WEAK_SIG_PATTERN='^(md2|md5|sha1)WithRSAEncryption$|^ecdsa-with-SHA1$|^dsa-with-sha1$'

# ═══════════════════════════════════════════════════════════════════════════════
# TRANSLATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

translate_eapol() {
    [ -n "$1" ] && echo "${EAPOL_TYPES[$1]:-Unknown($1)}"
}

translate_eap() {
    [ -n "$1" ] && echo "${EAP_TYPES[$1]:-Unknown($1)}"
}

translate_code() {
    [ -n "$1" ] && echo "${EAP_CODES[$1]:-Unknown($1)}"
}

translate_tls() {
    [ -n "$1" ] && echo "${TLS_TYPES[$1]:-Unknown($1)}"
}

# Translate comma-separated TLS values into array
format_tls_values_array() {
    local values="$1"
    local -n arr=$2 # Reference to output array

    IFS=',' read -ra tls_array <<< "$values"
    for tls_val in "${tls_array[@]}"; do
        tls_val=$(echo "$tls_val" | xargs)
        arr+=("TLS: $(translate_tls "$tls_val")($tls_val)")
    done
}

# Exact match in a comma-separated list ("11" must not match "110")
list_contains() {
    local item
    IFS=',' read -ra items <<< "$1"
    for item in "${items[@]}"; do
        [ "$(echo "$item" | xargs)" = "$2" ] && return 0
    done
    return 1
}

# Verbose decode of one frame. In live mode the frame may not be on disk yet.
frame_verbose() {
    local out tries=0
    while [ $tries -lt 10 ]; do
        out=$(tshark -r "$PCAP_FILE" -Y "frame.number == $1" -V 2>/dev/null)
        [ -n "$out" ] && break
        [ "$LIVE_MODE" = "1" ] || break
        sleep 0.2
        tries=$((tries + 1))
    done
    echo "$out"
}

# Only the first certificate of the chain (= the sender's own certificate)
first_cert() {
    awk '/Certificate Length:/{n++} n==1'
}

# Output: subject_dn|issuer_dn|not_before|not_after|signature_algorithm
extract_cert_info() {
    local cert=$(echo "$1" | first_cert)
    local issuer=$(echo "$cert" | grep -A1 "issuer: rdnSequence" | grep -m1 "rdnSequence:" | sed 's/.*items* (\(.*\))$/\1/')
    local subject=$(echo "$cert" | grep -A1 "subject: rdnSequence" | grep -m1 "rdnSequence:" | sed 's/.*items* (\(.*\))$/\1/')
    local not_before=$(echo "$cert" | grep -A1 "notBefore:" | grep -E "utcTime:|generalizedTime:" | head -1 | sed -E 's/.*(utcTime|generalizedTime): //')
    local not_after=$(echo "$cert" | grep -A1 "notAfter:" | grep -E "utcTime:|generalizedTime:" | head -1 | sed -E 's/.*(utcTime|generalizedTime): //')
    local sig_alg=$(echo "$cert" | grep -m1 "algorithmIdentifier (" | sed -n 's/.*algorithmIdentifier (\(.*\))/\1/p')
    echo "$subject|$issuer|$not_before|$not_after|$sig_alg"
}

# "id-at-commonName=foo,id-at-organizationName=bar" -> "foo"
dn_cn() {
    local cn=$(echo "$1" | grep -o 'id-at-commonName=[^,]*' | head -1 | cut -d= -f2-)
    echo "${cn:-$1}"
}

# EXPIRED / NOT_YET_VALID relative to the capture time of the frame
cert_validity_flag() {
    local nb na ref=${3%.*}
    nb=$(date -u -d "${1% (UTC)}" +%s 2>/dev/null)
    na=$(date -u -d "${2% (UTC)}" +%s 2>/dev/null)
    [ -z "$ref" ] && ref=$(date -u +%s)
    if [ -n "$na" ] && [ "$ref" -gt "$na" ]; then
        echo "EXPIRED"
    elif [ -n "$nb" ] && [ "$ref" -lt "$nb" ]; then
        echo "NOT_YET_VALID"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# PER-FRAME PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

TSHARK_FIELDS=(-e frame.number -e eapol.type -e eap.type -e eap.code -e eap.identity
    -e tls.handshake.type -e tls.handshake.version -e frame.time_epoch
    -e tls.handshake.extensions.supported_version)

process_eap() {
    local method_seen=0

    # Use pipe separator (|) instead of tab to avoid issues with empty fields
    while IFS='|' read -r frame_num eapol_type eap_type eap_code eap_identity tls_handshake tls_version frame_time tls_supported; do
        [ -z "$frame_num" ] && continue

        local interesting_lines=()

        # A real method (anything beyond Identity/Notification/Nak) was requested
        [ "$eap_code" = "1" ] && [ -n "$eap_type" ] && [ "$eap_type" -ge 4 ] 2>/dev/null && method_seen=1

        if [ -n "$eap_identity" ]; then
            interesting_lines+=("Identity: $eap_identity")
            if [ "$eap_code" = "2" ] && [[ ! "$eap_identity" =~ ^(anonymous|@) ]]; then
                interesting_lines+=("${YELLOW}⚠ [IDENTITY-EXPOSED]${RESET}")
            fi
        elif [ "$eap_type" = "3" ]; then
            interesting_lines+=("Client refused method ${YELLOW}⚠ [DOWNGRADE-POSSIBLE]${RESET}")
        elif [ -n "${EAP_WEAK_TYPES[${eap_type:-0}]}" ] && [ "$eap_code" = "1" ]; then
            interesting_lines+=("Server offers $(translate_eap "$eap_type") ${YELLOW}⚠ [WEAK-METHOD]${RESET}")
        elif [ -n "${EAP_WEAK_TYPES[${eap_type:-0}]}" ] && [ "$eap_code" = "2" ]; then
            interesting_lines+=("Client answered $(translate_eap "$eap_type") ${RED}⚠ [WEAK-METHOD]${RESET}")
        elif [ -n "$tls_handshake" ]; then
            format_tls_values_array "$tls_handshake" interesting_lines

            if list_contains "$tls_handshake" "2" || list_contains "$tls_handshake" "11"; then
                local verbose=$(frame_verbose "$frame_num")

                if list_contains "$tls_handshake" "2"; then
                    [ "$tls_supported" = "0x0304" ] && interesting_lines+=("TLS 1.3 - certificate is encrypted")
                    case "$tls_version" in
                        0x0300) interesting_lines+=("${YELLOW}⚠ [OLD-TLS-VERSION]${RESET} SSL 3.0") ;;
                        0x0301) interesting_lines+=("${YELLOW}⚠ [OLD-TLS-VERSION]${RESET} TLS 1.0") ;;
                        0x0302) interesting_lines+=("${YELLOW}⚠ [OLD-TLS-VERSION]${RESET} TLS 1.1") ;;
                    esac
                    local cipher=$(echo "$verbose" | grep -m1 "Cipher Suite: " | sed -n 's/.*Cipher Suite: \([A-Za-z0-9_]*\).*/\1/p')
                    if [[ "$cipher" =~ $WEAK_CIPHER_PATTERN ]]; then
                        interesting_lines+=("${YELLOW}⚠ [WEAK-CIPHER]${RESET} $cipher")
                    fi
                fi

                if list_contains "$tls_handshake" "11"; then
                    local owner="server"
                    [ "$eap_code" = "2" ] && owner="client"
                    interesting_lines+=("┌ CERTIFICATE ($owner):")

                    local cert_subject cert_issuer cert_not_before cert_not_after cert_sig
                    IFS='|' read -r cert_subject cert_issuer cert_not_before cert_not_after cert_sig <<< "$(extract_cert_info "$verbose")"

                    local self_signed_flag=""
                    if [ -n "$cert_subject" ] && [ "$cert_subject" = "$cert_issuer" ]; then
                        self_signed_flag=" ${YELLOW}⚠ [SELF-SIGNED]${RESET}"
                    fi
                    [ -n "$cert_subject" ] && interesting_lines+=("  CN: $(dn_cn "$cert_subject")$self_signed_flag")
                    [ -n "$cert_issuer" ] && interesting_lines+=("  Issuer: $(dn_cn "$cert_issuer")")

                    if [ -n "$cert_not_before" ] || [ -n "$cert_not_after" ]; then
                        local valtext="  Valid: $cert_not_before to $cert_not_after"
                        case "$(cert_validity_flag "$cert_not_before" "$cert_not_after" "$frame_time")" in
                            EXPIRED) valtext+=" ${YELLOW}⚠ [CERT-EXPIRED]${RESET}" ;;
                            NOT_YET_VALID) valtext+=" ${YELLOW}⚠ [CERT-NOT-YET-VALID]${RESET}" ;;
                        esac
                        interesting_lines+=("$valtext")
                    fi

                    if [[ "$cert_sig" =~ $WEAK_SIG_PATTERN ]]; then
                        interesting_lines+=("  Signature: $cert_sig ${YELLOW}⚠ [WEAK-SIGNATURE]${RESET}")
                    fi

                    # RSA key size of the first certificate (modulus without leading 00)
                    local modulus=""
                    if echo "$verbose" | first_cert | grep -q "modulus:"; then
                        modulus=$(tshark -r "$PCAP_FILE" -Y "frame.number == $frame_num" -T fields -e pkcs1.modulus 2>/dev/null | cut -d, -f1)
                        modulus=${modulus#00}
                    fi
                    if [ -n "$modulus" ] && [ $(( ${#modulus} * 4 )) -lt 2048 ]; then
                        interesting_lines+=("  RSA key: $(( ${#modulus} * 4 )) bit ${YELLOW}⚠ [WEAK-KEY]${RESET}")
                    fi

                    interesting_lines+=("└")
                fi
            fi
        fi

        # Success/Failure (overwrites everything)
        if [ "$eap_code" = "3" ]; then
            if [ "$method_seen" = "0" ]; then
                interesting_lines=("${GREEN}✓ SUCCESS${RESET} ${YELLOW}⚠ [NO-METHOD]${RESET}")
            else
                interesting_lines=("${GREEN}✓ SUCCESS${RESET}")
            fi
            method_seen=0
        elif [ "$eap_code" = "4" ]; then
            interesting_lines=("${RED}✗ FAIL${RESET}")
            method_seen=0
        fi

        printf "%-6s | %-20s | %-20s | %-20s | %b\n" \
            "$frame_num" \
            "$(translate_eapol "$eapol_type")" \
            "$(translate_eap "$eap_type")" \
            "$(translate_code "$eap_code")" \
            "${interesting_lines[0]}"

        # Additional lines (TLS entries, certificate details)
        for ((i=1; i<${#interesting_lines[@]}; i++)); do
            printf "%-6s | %-20s | %-20s | %-20s | %b\n" "" "" "" "" "${interesting_lines[$i]}"
        done
    done
}

print_header() {
    echo -e "${GRAY}$(printf '%-6s | %-20s | %-20s | %-20s | %-80s' "Frame" "EAPOL" "EAP" "Code" "Interesting")${RESET}"
    echo -e "${GRAY}$(printf '%-6s | %-20s | %-20s | %-20s | %-80s' "------" "--------------------" "--------------------" "--------------------" "$(printf '=%.0s' {1..80})")${RESET}"
}

# Ask to keep the live capture, then remove the temp file
cleanup() {
    if [ -n "$TEMP_PCAP" ] && [ -f "$TEMP_PCAP" ]; then
        echo ""
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo -e "${CYAN_BOLD}LIVE CAPTURE finished - go out and preach!${RESET}"
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo ""

        read -p "Save the capture as a pcap file? (y/n): " -n 1 -r response
        echo ""

        if [[ $response =~ ^[Yy]$ ]]; then
            local output_file="eap_capture_$(date +%Y%m%d_%H%M%S).pcapng"
            cp "$TEMP_PCAP" "$output_file"
            echo "✓ Saved: $output_file"
        else
            echo "✓ Discarded"
        fi

        rm -f "$TEMP_PCAP"
    fi
}

trap cleanup EXIT

# ═══════════════════════════════════════════════════════════════════════════════
# HELP
# ═══════════════════════════════════════════════════════════════════════════════

usage() {
    echo ""
    echo -e "${GRAY}###########################################################################################${RESET}"
    echo -e "${GRAY}#${RESET}${CYAN_BOLD} eapreach - reach each & preach${RESET}                                                          ${GRAY}#${RESET}"
    echo -e "${GRAY}#${RESET}${CYAN} Reach each EAP packet. Discover configuration reality. Preach configuration compliance.${RESET} ${GRAY}#${RESET}"
    echo -e "${GRAY}#${RESET} It's a tshark based EAP packet analyzer with certificate analysis included.             ${GRAY}#${RESET}"
    echo -e "${GRAY}###########################################################################################${RESET}"
    echo ""
    echo -e "${CYAN_BOLD}USAGE:${RESET}"
    echo "    $0 <pcap_file>              analyze a pcap/pcapng file"
    echo "    $0 -i <interface>           live capture on a network interface"
    echo "    $0 -h                       display this help"
    echo ""
    echo -e "${CYAN_BOLD}EXAMPLES:${RESET}"
    echo "    $0 test.pcapng"
    echo "    $0 -i enp2s0                (as root or as user - sudo is used if needed)"
    echo ""
    echo -e "${CYAN_BOLD}CLIENT SETUP:${RESET}"
    echo -e "    ${GRAY}Run eapreach on the 802.1X client while it authenticates (LAN or WLAN).${RESET}"
    echo -e "    ${GRAY}Switch the client's EAP method one by one and watch what the network answers.${RESET}"
    echo -e "    ${GRAY}RADIUS (authenticator <-> AAA server) is never visible from the client.${RESET}"
    echo ""
    echo -e "${CYAN_BOLD}REQUIREMENTS:${RESET}"
    echo -e "    ${GRAY}Linux, bash 4.3+, tshark, coreutils (date, tee, mktemp), grep, sed, awk, xargs, ip${RESET}"
    echo -e "    ${GRAY}Live capture: root or sudo${RESET}"
    echo ""
    echo -e "${CYAN_BOLD}SECURITY WARNINGS:${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [WEAK-METHOD]${RESET} MD5-Challenge, OTP, GTC or LEAP"
    echo -e "    ${GRAY}  The server never proves its identity and no keys are derived.${RESET}"
    echo -e "    ${GRAY}  A captured MD5/LEAP answer can be cracked offline (dictionary attack).${RESET}"
    echo -e "    ${GRAY}  Offered by the server = misconfiguration. Answered by the client = password at risk.${RESET}"
    echo -e "    ${GRAY}  → Disable these methods on the RADIUS server.${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [DOWNGRADE-POSSIBLE]${RESET} Legacy Nak"
    echo -e "    ${GRAY}  The server lets the client negotiate the method (RFC 3748, 7.8).${RESET}"
    echo -e "    ${GRAY}  A client that allows a weaker method will get it - and a Nak can be forged.${RESET}"
    echo -e "    ${GRAY}  → Allow only the EAP methods you need on the RADIUS server.${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [SELF-SIGNED]${RESET} Server certificate signed by itself"
    echo -e "    ${GRAY}  Typically the untouched default certificate of the RADIUS server or device.${RESET}"
    echo -e "    ${GRAY}  Clients cannot verify it, so users learn to accept any certificate -${RESET}"
    echo -e "    ${GRAY}  including the one of a rogue access point (evil twin, credential theft).${RESET}"
    echo -e "    ${GRAY}  → Use a certificate from your own CA, roll out the CA, enforce validation.${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [CERT-EXPIRED] [CERT-NOT-YET-VALID] [WEAK-SIGNATURE] [WEAK-KEY]${RESET}"
    echo -e "    ${GRAY}  Certificate outside its validity at capture time, signed with MD5/SHA-1,${RESET}"
    echo -e "    ${GRAY}  or RSA key below 2048 bit. → Re-issue the certificate.${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [OLD-TLS-VERSION] [WEAK-CIPHER]${RESET}"
    echo -e "    ${GRAY}  Server chose TLS 1.1 or older, or an RC4/DES/3DES/NULL/EXPORT/anon cipher.${RESET}"
    echo -e "    ${GRAY}  → Require TLS 1.2+ with modern ciphers on the RADIUS server.${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [IDENTITY-EXPOSED]${RESET} Outer identity is not anonymous"
    echo -e "    ${GRAY}  The username is readable by anyone on the wire.${RESET}"
    echo -e "    ${GRAY}  → Set an anonymous outer identity (e.g. anonymous@example.com) on the client.${RESET}"
    echo ""
    echo -e "    ${YELLOW}⚠ [NO-METHOD]${RESET} EAP-Success without authentication method"
    echo -e "    ${GRAY}  The port was opened without any credential check.${RESET}"
    echo -e "    ${GRAY}  Possible causes: fail-open / critical-auth rule, accept-all policy.${RESET}"
    echo -e "    ${GRAY}  → Check the authenticator and RADIUS policy for this port.${RESET}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    local mode="file"
    local input=""

    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -i|--interface)
                mode="live"
                input="$2"
                shift 2
                ;;
            *)
                input="$1"
                shift
                ;;
        esac
    done

    if [ -z "$input" ]; then
        echo "Error: no input given"
        usage
        exit 1
    fi

    if ! command -v tshark &> /dev/null; then
        echo "Error: tshark not found"
        exit 1
    fi

    echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN_BOLD}EAP PACKET ANALYSIS started - you can reach each of them!${RESET}"
    echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GRAY}Run with -h for ${YELLOW}security warning${GRAY} explanations${RESET}"
    echo ""

    if [ "$mode" = "file" ]; then
        if [ ! -f "$input" ]; then
            echo "Error: file '$input' not found"
            exit 1
        fi

        echo "File: $input"
        echo "Mode: Offline analysis"
        echo ""
        print_header

        PCAP_FILE="$input"
        LIVE_MODE="0"
        tshark -r "$input" -Y "eap or eapol" -T fields -E separator='|' "${TSHARK_FIELDS[@]}" 2>/dev/null | process_eap

        echo ""
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo -e "${CYAN_BOLD}OFFLINE ANALYSIS finished - go out and preach!${RESET}"
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo ""
    else
        if ! ip link show "$input" &>/dev/null; then
            echo "Error: interface '$input' not found"
            exit 1
        fi

        local SUDO=""
        [ "$EUID" -ne 0 ] && SUDO="sudo"

        echo "Interface: $input"
        echo "Mode: Live capture (Ctrl+C to stop)"
        echo ""
        print_header

        # Only the capture itself runs privileged. It streams the packets once:
        # tee stores them in a user-owned temp file (certificate details, saving),
        # the second tshark decodes them live. No polling, no duplicate lines.
        TEMP_PCAP=$(mktemp "${TMPDIR:-/tmp}/eapreach_XXXXXX.pcapng")
        PCAP_FILE="$TEMP_PCAP"
        LIVE_MODE="1"

        $SUDO tshark -Q -l -i "$input" -w - 2>/dev/null \
            | tee "$TEMP_PCAP" \
            | tshark -l -i - -Y "eap or eapol" -T fields -E separator='|' "${TSHARK_FIELDS[@]}" 2>/dev/null \
            | process_eap
    fi
}

main "$@"
