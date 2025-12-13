#!/bin/bash

# eapreach - reach each & preach
# Reach each EAP packet. Discover configuration reality. Preach configuration compliance.
# It's a tshark based EAP packet analyzer with certificate analysis included.

# Copyright® 2025 BerziOnline
# eapreach v1.0

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

# EAPOL Type Translation
declare -A EAPOL_TYPES=(
    [0]="EAP Packet"
    [1]="Start"
    [2]="Logoff"
    [3]="Success"
    [4]="Failure"
)

# EAP Type Translation
declare -A EAP_TYPES=(
    [1]="Identity"
    [2]="Notification"
    [3]="Legacy Nak"
    [4]="MD5-Challenge"
    [6]="Reserved"
    [13]="EAP-TLS"
    [21]="EAP-TTLS"
    [25]="PEAP"
    [26]="PEAP"
    [29]="EAP-MAKA"
    [32]="EAP-FAST"
    [43]="EAP-TEAP"
)

# EAP Code Translation
declare -A EAP_CODES=(
    [1]="Request"
    [2]="Response"
    [3]="Success"
    [4]="Failure"
)

# TLS Handshake Type Translation
declare -A TLS_TYPES=(
    [1]="Client Hello"
    [2]="Server Hello"
    [11]="Certificate"
    [12]="Server Key Exchange"
    [14]="Server Hello Done"
    [16]="Client Key Exchange"
    [20]="Change Cipher Spec"
    [23]="Application Data"
)

# ═══════════════════════════════════════════════════════════════════════════════
# TRANSLATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

translate_eapol() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
    else
        echo "${EAPOL_TYPES[$value]:-Unknown($value)}"
    fi
}

translate_eap() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
    else
        echo "${EAP_TYPES[$value]:-Unknown($value)}"
    fi
}

translate_code() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
    else
        echo "${EAP_CODES[$value]:-Unknown($value)}"
    fi
}

translate_tls() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
    else
        echo "${TLS_TYPES[$value]:-Unknown($value)}"
    fi
}

# Translate comma-separated TLS values into array
format_tls_values_array() {
    local values="$1"
    local -n arr=$2 # Reference to output array

    # Split by comma
    IFS=',' read -ra tls_array <<< "$values"

    for tls_val in "${tls_array[@]}"; do
        # Trim whitespace
        tls_val=$(echo "$tls_val" | xargs)

        local tls_name=$(translate_tls "$tls_val")
        arr+=("TLS: $tls_name($tls_val)")
    done
}

# Extract certificate information from verbose output
extract_cert_info() {
    local verbose_output="$1"
    
    # Extrahiere Subject CN
    local subject=$(echo "$verbose_output" | grep -A 10 "subject: rdnSequence" | grep "uTF8String:" | head -1 | sed 's/.*uTF8String: //')
    
    # Extrahiere Issuer CN
    local issuer=$(echo "$verbose_output" | grep -A 10 "issuer: rdnSequence" | grep "uTF8String:" | head -1 | sed 's/.*uTF8String: //')
    
    # Extrahiere notBefore (Valid from)
    local not_before=$(echo "$verbose_output" | grep -A 1 "notBefore:" | grep "utcTime:" | head -1 | sed 's/.*utcTime: //')
    
    # Extrahiere notAfter (Valid until)
    local not_after=$(echo "$verbose_output" | grep -A 1 "notAfter:" | grep "utcTime:" | head -1 | sed 's/.*utcTime: //')
    
    # Rückgabe als pipe-separated string
    echo "$subject|$issuer|$not_before|$not_after"
}

# Check if certificate is self-signed using cached verbose output
is_self_signed_from_verbose() {
    local verbose_output="$1"
    
    # Extrahiere Subject CN aus verbose output
    local subject=$(echo "$verbose_output" | grep -A 10 "subject: rdnSequence" | grep "uTF8String:" | head -1 | sed 's/.*uTF8String: //')
    
    # Extrahiere Issuer CN aus verbose output
    local issuer=$(echo "$verbose_output" | grep -A 10 "issuer: rdnSequence" | grep "uTF8String:" | head -1 | sed 's/.*uTF8String: //')
    
    if [ -n "$subject" ] && [ -n "$issuer" ] && [ "$subject" = "$issuer" ]; then
        return 0  # true (selbstsigniert)
    fi
    return 1  # false
}

# Process input and decode information - only NEW frames in live mode
process_eap() {
    # Use pipe separator (|) instead of tab to avoid issues with empty fields
    while IFS='|' read -r frame_num eapol_type eap_type eap_code eap_identity md5_value tls_handshake; do
        # Skip header row from tshark
        if [ "$frame_num" = "frame.number" ]; then
            continue
        fi

        # Skip empty lines
        if [ -z "$frame_num" ]; then
            continue
        fi

        # Check if frame was already processed (only in live mode with STATE_FILE set)
        if [ -n "$STATE_FILE" ] && [ -f "$STATE_FILE" ] && grep -q "^$frame_num\$" "$STATE_FILE" 2>/dev/null; then
            continue
        fi

        # Mark this frame as processed (only in live mode with STATE_FILE set)
        if [ -n "$STATE_FILE" ]; then
            echo "$frame_num" >> "$STATE_FILE" 2>/dev/null
        fi

        local interesting_lines=()

        # Determine what to show in Interesting column
        if [ -n "$eap_identity" ] && [ "$eap_identity" != "0" ]; then
            interesting_lines+=("Identity: $eap_identity")
        elif [ -n "$md5_value" ]; then
            interesting_lines+=("MD5: $md5_value ${YELLOW}⚠ [DEPRECATED]${RESET}")
        elif [ -n "$eap_type" ] && [ "$eap_type" = "3" ]; then
            # Legacy Nak (EAP Type 3) detected
            interesting_lines+=("Client falling back to weaker method ${YELLOW}⚠ [DOWNGRADE]${RESET}")
        elif [ -n "$tls_handshake" ]; then
            # Format TLS values into array (one per line)
            format_tls_values_array "$tls_handshake" interesting_lines

            # Wenn Certificate(11) dabei ist → Zertifikat anzeigen
            if [[ "$tls_handshake" == *"11"* ]]; then
                interesting_lines+=("┌ CERTIFICATE:")
                
                # Hole verbose output für diesen Frame
                if [ -n "$PCAP_FILE" ] && [ -f "$PCAP_FILE" ]; then
                    local verbose=$(tshark -r "$PCAP_FILE" -Y "frame.number == $frame_num" -V 2>/dev/null)
                    
                    # Extrahiere Zertifikatsinformationen
                    local cert_info=$(extract_cert_info "$verbose")
                    IFS='|' read -r cert_cn cert_issuer cert_not_before cert_not_after <<< "$cert_info"
                    
                    # Prüfe ob selbstsigniert
                    local self_signed_flag=""
                    if is_self_signed_from_verbose "$verbose"; then
                        self_signed_flag=" ${YELLOW}⚠ [SELF-SIGNED - MITM Risk]${RESET}"
                    fi
                    
                    # CN Line
                    if [ -n "$cert_cn" ]; then
                        interesting_lines+=("  CN: $cert_cn$self_signed_flag")
                    fi
                    
                    # Issuer Line
                    if [ -n "$cert_issuer" ]; then
                        interesting_lines+=("  Issuer: $cert_issuer")
                    fi
                    
                    # Validity Period
                    if [ -n "$cert_not_before" ] || [ -n "$cert_not_after" ]; then
                        interesting_lines+=("  Valid: $cert_not_before to $cert_not_after")
                    fi
                fi
                
                interesting_lines+=("└")
            fi
        fi

        # Check for Success/Failure (overwrites everything)
        if [ "$eap_code" = "3" ]; then
            interesting_lines=("${GREEN}✓ SUCCESS${RESET}")
        elif [ "$eap_code" = "4" ]; then
            interesting_lines=("${RED}✗ FAIL${RESET}")
        fi

        # Translate the values
        local eapol_name=$(translate_eapol "$eapol_type")
        local eap_name=$(translate_eap "$eap_type")
        local code_name=$(translate_code "$eap_code")

        # Print first line with Frame/EAPOL/EAP/Code
        printf "%-6s | %-20s | %-20s | %-20s | %b\n" \
            "$frame_num" \
            "$eapol_name" \
            "$eap_name" \
            "$code_name" \
            "${interesting_lines[0]}"

        # Print additional lines for extra TLS entries
        for ((i=1; i<${#interesting_lines[@]}; i++)); do
            printf "%-6s | %-20s | %-20s | %-20s | %b\n" \
                "" "" "" "" \
                "${interesting_lines[$i]}"
        done
    done
}

# Cleanup function for temp files
cleanup() {
    # Cleanup state file
    rm -f "$STATE_FILE" 2>/dev/null
    
    # Nur bei Live-Capture fragen, ob PCAP gespeichert werden soll
    if [ -n "$TEMP_PCAP" ] && [ -f "$TEMP_PCAP" ] && [ "$LIVE_MODE" = "1" ]; then
        echo ""
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo -e "${CYAN_BOLD}LIVE CAPTURE finished - go out and preach!${RESET}"
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo ""
        
        # Frage ob PCAP behalten werden soll
        read -p "Möchtest du die PCAP-Datei speichern? (j/n): " -n 1 -r response
        echo ""
        
        if [[ $response =~ ^[Jj]$ ]]; then
            local timestamp=$(date +%Y%m%d_%H%M%S)
            local output_file="eap_capture_$timestamp.pcapng"
            
            cp "$TEMP_PCAP" "$output_file"
            echo "✓ PCAP gespeichert: $output_file"
        else
            echo "✓ PCAP gelöscht"
        fi
        
        rm -f "$TEMP_PCAP" 2>/dev/null
    elif [ -n "$TEMP_PCAP" ] && [ -f "$TEMP_PCAP" ]; then
        rm -f "$TEMP_PCAP" 2>/dev/null
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Display usage information
usage() {
    echo ""
    echo -e "${GRAY}###########################################################################################${RESET}"
    echo -e "${GRAY}#${RESET}${CYAN_BOLD} eapreach - reach each & preach${RESET}                                                          ${GRAY}#${RESET}"
    echo -e "${GRAY}#${RESET}${CYAN} Reach each EAP packet. Discover configuration reality. Preach configuration compliance.${RESET} ${GRAY}#${RESET}"
    echo -e "${GRAY}#${RESET} It's a tshark based EAP packet analyzer with certificate analysis included.             ${GRAY}#${RESET}"
    echo -e "${GRAY}###########################################################################################${RESET}"
    echo ""
    echo -e "${CYAN_BOLD}USAGE:${RESET}"
    echo "    $0 <pcap_file>              analyze any pcap/pcapng file"
    echo "    $0 -i <interface>           live capture directly with a network interface"
    echo "    $0 -h                       display this help"
    echo ""
    echo -e "${CYAN_BOLD}EXAMPLES:${RESET}"
    echo "    $0 test.pcapng              analyze pre-captured pcap file \"test.pcapng\""
    echo "    $0 -i enp2s0                live capture on enp2s0"
    echo ""
    echo -e "${CYAN_BOLD}CLIENT SETUP:${RESET}"
    echo -e "    ${GRAY}eapreach is running direclty on the 802.1X-CLIENT during the authentication process.${RESET}"
    echo -e "    ${GRAY}You have to know, that offering 802.1X authentication methods is a client-side-setting.${RESET}"
    echo -e "    ${GRAY}This is why you want to analyze dot1x environments from client side by this tool here.${RESET}"
    echo ""
    echo -e "    ${GRAY}LAN (Ethernet):${RESET}"
    echo -e "    ${GRAY}    • client has to be connected to a \"normal\" configurated 802.1X edge port from the target network${RESET}"
    echo -e "    ${GRAY}    • the clients network interface need to be setup to use 802.1X${RESET}"
    echo -e "    ${GRAY}    • the 802.1X settings need to be varied through all the EAP methods you want to check - one by one${RESET}"
    echo -e "    ${GRAY}    • while doing that, just sniff a pcap or keep the live capture mode running from this tool here${RESET}"
    echo -e "    ${GRAY}    • pcap can be stored with eapreach while live capturing as well, so this is the recommended method${RESET}"
    echo ""
    echo -e "    ${GRAY}WLAN (Wi-Fi):${RESET}"
    echo -e "    ${GRAY}    • not really a difference to the LAN connection${RESET}"
    echo -e "    ${GRAY}    • client has to be connected to a 802.1X-SSID from the target network${RESET}"
    echo ""
    echo -e "    ${GRAY}SOFTWARE REQUIREMENTS:${RESET}"
    echo -e "    ${GRAY}    ✓ tshark (aus wireshark-common)${RESET}"
    echo -e "    ${GRAY}    ✓ Bash 4+, grep, sed, head${RESET}"
    echo -e "    ${GRAY}    ✓ sudo (für Packet Capture)${RESET}"
    echo ""
    echo -e "    ${GRAY}WHY ARE THERE NO RADIUS-SEGMENTS?${RESET}"
    echo -e "    ${GRAY}    eapreach displays EAPOL/EAP-traffic (Supplicant↔Authenticator)${RESET}"
    echo -e "    ${GRAY}    RADIUS is running in the backend and not at the edge (Authenticator↔AAA-Server), so you cannot see them here!${RESET}"
    echo -e "    ${GRAY}    → You are checking the client perspective from the edge (EAP-methods, certificates, success/failure)${RESET}"
    echo -e "    ${GRAY}    → The backend communication from authenticator to the AAA server (=RADIUS/TACACS+) is not relevant here${RESET}"
    echo -e "    ${GRAY}    → You want to analyze different opportunities and weaknesses related to the network access from client perspective${RESET}"
    echo ""
    echo -e "${CYAN_BOLD}SECURITY WARNINGS EXPLAINED:${RESET}"
    echo ""
    
    echo -e "    ${YELLOW}⚠ [DEPRECATED]${RESET} - MD5-Challenge Authentication"
    echo -e "    ${GRAY}─────────────────────────────────────────────────────────────${RESET}"
    echo -e "    ${GRAY}WHY DANGEROUS:${RESET}"
    echo -e "    ${GRAY}      • MD5 hash function is cryptographically broken (RFC 6151)${RESET}"
    echo -e "    ${GRAY}      • Collision attacks possible, making cracking feasible${RESET}"
    echo -e "    ${GRAY}      • Attackers can craft fake MD5 responses${RESET}"
    echo -e "    ${GRAY}      • No mutual authentication - server can't verify client legitimacy${RESET}"
    echo -e "    ${GRAY}${RESET}"
    echo -e "    ${GRAY}HOW TO EXPLOIT:${RESET}"
    echo -e "    ${GRAY}      1. Capture MD5 challenge hashes from network${RESET}"
    echo -e "    ${GRAY}      2. Perform offline dictionary/rainbow table attacks (~hours/minutes)${RESET}"
    echo -e "    ${GRAY}      3. Forge MD5 response and gain network access${RESET}"
    echo -e "    ${GRAY}      4. No detection possible - valid hash = valid credential${RESET}"
    echo -e "    ${GRAY}${RESET}"
    echo -e "    ${GRAY}REMEDIATION:${RESET}"
    echo -e "    ${GRAY}      → Disable MD5-Challenge on RADIUS/NAS servers immediately${RESET}"
    echo -e "    ${GRAY}      → Configure only: EAP-TLS, EAP-TTLS, PEAP, EAP-FAST${RESET}"
    echo -e "    ${GRAY}      → Force minimum TLS 1.2 for tunnel-based methods${RESET}"
    echo -e "    ${GRAY}      → Audit all devices - replace hardware that can't do EAP-TLS${RESET}"
    echo ""
    
    echo -e "    ${YELLOW}⚠ [DOWNGRADE]${RESET} - Legacy NAK Fallback Attack"
    echo -e "    ${GRAY}─────────────────────────────────────────────────────────────${RESET}"
    echo -e "    ${GRAY}WHY DANGEROUS:${RESET}"
    echo -e "    ${GRAY}      • Legacy NAK forces server to negotiate weaker EAP methods${RESET}"
    echo -e "    ${GRAY}      • RFC 3748 explicitly lists as attack vector (Ch. 4.3)${RESET}"
    echo -e "    ${GRAY}      • Can be injected by attacker to force downgrade${RESET}"
    echo -e "    ${GRAY}      • Enables attacks on deprecated auth methods (MD5, etc.)${RESET}"
    echo -e "    ${GRAY}${RESET}"
    echo -e "    ${GRAY}HOW TO EXPLOIT:${RESET}"
    echo -e "    ${GRAY}      1. Attacker intercepts EAP-Request (e.g., for EAP-TTLS)${RESET}"
    echo -e "    ${GRAY}      2. Injects Legacy NAK: 'Client can't do this method'${RESET}"
    echo -e "    ${GRAY}      3. Server falls back to MD5-Challenge (weaker)${RESET}"
    echo -e "    ${GRAY}      4. Attacker cracks MD5 instead of TLS (much easier)${RESET}"
    echo -e "    ${GRAY}${RESET}"
    echo -e "    ${GRAY}REMEDIATION:${RESET}"
    echo -e "    ${GRAY}      → REJECT Legacy NAK responses on all NAS/RADIUS servers${RESET}"
    echo -e "    ${GRAY}      → Enable only strong EAP types (whitelist model)${RESET}"
    echo -e "    ${GRAY}      → Monitor for Legacy NAK in logs → indicates old hardware${RESET}"
    echo -e "    ${GRAY}      → Identify & replace non-compliant devices${RESET}"
    echo -e "    ${GRAY}      → Consider EAP-TLS enforcement only (zero downgrade risk)${RESET}"
    echo ""
    
    echo -e "    ${YELLOW}⚠ [SELF-SIGNED]${RESET} - Self-Signed Certificate"
    echo -e "    ${GRAY}─────────────────────────────────────────────────────────────${RESET}"
    echo -e "    ${GRAY}WHY DANGEROUS:${RESET}"
    echo -e "    ${GRAY}      • No Certificate Authority validation (Subject == Issuer)${RESET}"
    echo -e "    ${GRAY}      • Client can't verify server identity authentically${RESET}"
    echo -e "    ${GRAY}      • Perfect for Man-in-the-Middle (MITM) attacks${RESET}"
    echo -e "    ${GRAY}      • Attacker can present fake cert - client accepts (no CA check)${RESET}"
    echo -e "    ${GRAY}${RESET}"
    echo -e "    ${GRAY}HOW TO EXPLOIT:${RESET}"
    echo -e "    ${GRAY}      1. Attacker sets up rogue AP on same network${RESET}"
    echo -e "    ${GRAY}      2. Client connects, server presents self-signed cert${RESET}"
    echo -e "    ${GRAY}      3. Client has NO way to verify legitimacy (no CA chain)${RESET}"
    echo -e "    ${GRAY}      4. Attacker acts as proxy: Client↔Attacker↔Real Server${RESET}"
    echo -e "    ${GRAY}      5. Attacker decrypts/modifies/captures all EAP traffic${RESET}"
    echo -e "    ${GRAY}${RESET}"
    echo -e "    ${GRAY}REMEDIATION:${RESET}"
    echo -e "    ${GRAY}      → Use ONLY certificates from trusted CAs (DigiCert, Let's Encrypt, etc.)${RESET}"
    echo -e "    ${GRAY}      → Import CA root cert on all clients (certificate pinning)${RESET}"
    echo -e "    ${GRAY}      → Verify cert chain on client side (WPA2-Enterprise policy)${RESET}"
    echo -e "    ${GRAY}      → Monitor for self-signed certs in logs${RESET}"
    echo -e "    ${GRAY}      → Educate users: REJECT unknown certificate warnings${RESET}"
    echo ""
}

# Main script logic
main() {
    local mode="file"
    local input=""

    # Parse arguments
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

    # Validate input
    if [ -z "$input" ]; then
        echo "Fehler: Keine Eingabe angegeben"
        usage
        exit 1
    fi

    # Check if tshark is available
    if ! command -v tshark &> /dev/null; then
        echo "Fehler: tshark nicht gefunden. Bitte wireshark-common installieren."
        exit 1
    fi

    echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN_BOLD}EAP PACKET ANALYSIS started - you can reach each of them!${RESET}"
    echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GRAY}Run with -h for ${YELLOW}security warning${GRAY} explanations${RESET}"
    echo ""

    # File mode
    if [ "$mode" = "file" ]; then
        if [ ! -f "$input" ]; then
            echo "Fehler: Datei '$input' nicht gefunden"
            exit 1
        fi

        echo "Datei: $input"
        echo "Modus: Offline Analyse"
        echo ""

        # Print header in GRAY
        echo -e "${GRAY}$(printf '%-6s | %-20s | %-20s | %-20s | %-80s' "Frame" "EAPOL" "EAP" "Code" "Interesting")${RESET}"
        echo -e "${GRAY}$(printf '%-6s | %-20s | %-20s | %-20s | %-80s' "------" "--------------------" "--------------------" "--------------------" "$(printf '=%.0s' {1..80})")${RESET}"

        # Set global PCAP_FILE for use in functions
        export PCAP_FILE="$input"
        export LIVE_MODE="0"
        
        # No state file for file mode (process all frames)
        STATE_FILE=""

        tshark -r "$input" -Y "eap or eapol" -T fields -E separator='|' \
            -e frame.number \
            -e eapol.type \
            -e eap.type \
            -e eap.code \
            -e eap.identity \
            -e eap.md5.value \
            -e tls.handshake.type 2>/dev/null | process_eap

        # Print offline analysis completion banner
        echo ""
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo -e "${CYAN_BOLD}OFFLINE ANALYSIS finished - go out and preach!${RESET}"
        echo -e "${CYAN_BOLD}═════════════════════════════════════════════════════════════════${RESET}"
        echo ""

    # Live mode
    else
        # Check if interface exists
        if ! ip link show "$input" &>/dev/null; then
            echo "Fehler: Interface '$input' nicht gefunden"
            exit 1
        fi

        echo "Interface: $input"
        echo "Modus: Live Capture (Ctrl+C zum Beenden)"
        echo ""

        # Print header in GRAY
        echo -e "${GRAY}$(printf '%-6s | %-20s | %-20s | %-20s | %-80s' "Frame" "EAPOL" "EAP" "Code" "Interesting")${RESET}"
        echo -e "${GRAY}$(printf '%-6s | %-20s | %-20s | %-20s | %-80s' "------" "--------------------" "--------------------" "--------------------" "$(printf '=%.0s' {1..80})")${RESET}"

        # Create a temporary file for capturing packets
        TEMP_PCAP=$(mktemp /tmp/eap_analyzer_XXXXXX.pcapng)
        STATE_FILE=$(mktemp /tmp/eap_analyzer_state_XXXXXX.txt)
        
        export PCAP_FILE="$TEMP_PCAP"
        export STATE_FILE="$STATE_FILE"
        export LIVE_MODE="1"

        # Need sudo for live capture
        if [ "$EUID" -ne 0 ]; then
            # Start tshark in background to capture to temp file
            sudo tshark -i "$input" -w "$TEMP_PCAP" 2>/dev/null &
            local CAPTURE_PID=$!
            
            # Sleep a moment to ensure tshark is capturing
            sleep 0.5

            # Now run the analysis on the temp file in a loop
            while kill -0 $CAPTURE_PID 2>/dev/null; do
                tshark -r "$TEMP_PCAP" -Y "eap or eapol" -T fields -E separator='|' \
                    -e frame.number \
                    -e eapol.type \
                    -e eap.type \
                    -e eap.code \
                    -e eap.identity \
                    -e eap.md5.value \
                    -e tls.handshake.type 2>/dev/null | process_eap
                
                sleep 1
            done

            # Final read after capture stops
            tshark -r "$TEMP_PCAP" -Y "eap or eapol" -T fields -E separator='|' \
                -e frame.number \
                -e eapol.type \
                -e eap.type \
                -e eap.code \
                -e eap.identity \
                -e eap.md5.value \
                -e tls.handshake.type 2>/dev/null | process_eap
        else
            # Start tshark in background to capture to temp file
            tshark -i "$input" -w "$TEMP_PCAP" 2>/dev/null &
            local CAPTURE_PID=$!
            
            # Sleep a moment to ensure tshark is capturing
            sleep 0.5

            # Now run the analysis on the temp file in a loop
            while kill -0 $CAPTURE_PID 2>/dev/null; do
                tshark -r "$TEMP_PCAP" -Y "eap or eapol" -T fields -E separator='|' \
                    -e frame.number \
                    -e eapol.type \
                    -e eap.type \
                    -e eap.code \
                    -e eap.identity \
                    -e eap.md5.value \
                    -e tls.handshake.type 2>/dev/null | process_eap
                
                sleep 1
            done

            # Final read after capture stops
            tshark -r "$TEMP_PCAP" -Y "eap or eapol" -T fields -E separator='|' \
                -e frame.number \
                -e eapol.type \
                -e eap.type \
                -e eap.code \
                -e eap.identity \
                -e eap.md5.value \
                -e tls.handshake.type 2>/dev/null | process_eap
        fi
    fi
}

# Run main function
main "$@"
