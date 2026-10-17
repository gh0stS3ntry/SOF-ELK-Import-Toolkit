#!/usr/bin/env bash
set -euo pipefail

# Configure a standalone SOF-ELK Elasticsearch node for direct bulk ingestion
# from a designated importer VM.
#
# Usage:
#   sudo ./SOF-ELK_ConfigureRemoteIngest.sh <IMPORTER_VM_IP>
#
# The script:
#   1. Validates the importer VM IPv4 address.
#   2. Backs up /etc/elasticsearch/elasticsearch.yml.
#   3. Ensures network.host: 0.0.0.0 and discovery.type: single-node.
#   4. Allows only the supplied importer IP to reach TCP/9200 via firewalld.
#   5. Restarts Elasticsearch.
#   6. Verifies the local Elasticsearch API and listening socket.
#
# Notes:
#   - This assumes Elasticsearch is installed under /etc/elasticsearch.
#   - This assumes firewalld manages the active host firewall.
#   - Elasticsearch security/authentication is not enabled or modified here.
#

ES_CONFIG="/etc/elasticsearch/elasticsearch.yml"
ES_SERVICE="elasticsearch"
ES_PORT="9200"

usage() {
    echo "Usage: sudo $0 <IMPORTER_VM_IP>"
    echo "Example: sudo $0 192.168.233.145"
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

info() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || fail "This script must be run as root (use sudo)."
}

validate_ipv4() {
    local ip="$1"
    local a b c d extra

    IFS='.' read -r a b c d extra <<< "$ip"
    [[ -z "${extra:-}" ]] || return 1
    [[ -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] || return 1

    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done

    return 0
}

backup_config() {
    local stamp backup
    stamp="$(date +%Y%m%d-%H%M%S)"
    backup="${ES_CONFIG}.bak.${stamp}"
    cp -a "$ES_CONFIG" "$backup"
    info "Backed up Elasticsearch configuration to $backup"
}

set_yaml_key() {
    local key="$1"
    local value="$2"
    local tmp

    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { done=0 }
        {
            if ($0 ~ "^[[:space:]]*" key "[[:space:]]*:") {
                if (!done) {
                    print key ": " value
                    done=1
                }
                next
            }
            print
        }
        END {
            if (!done) print key ": " value
        }
    ' "$ES_CONFIG" > "$tmp"

    chown --reference="$ES_CONFIG" "$tmp"
    chmod --reference="$ES_CONFIG" "$tmp"
    mv "$tmp" "$ES_CONFIG"
}

get_firewalld_zone() {
    local iface zone

    # Prefer the interface used for the default route.
    iface="$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')"
    if [[ -n "$iface" ]]; then
        zone="$(firewall-cmd --get-zone-of-interface="$iface" 2>/dev/null || true)"
        if [[ -n "$zone" && "$zone" != "no zone" ]]; then
            echo "$zone"
            return 0
        fi
    fi

    # Fall back to the first active zone.
    zone="$(firewall-cmd --get-active-zones 2>/dev/null | awk 'NR==1 {print $1}')"
    [[ -n "$zone" ]] || return 1
    echo "$zone"
}

configure_firewalld() {
    local importer_ip="$1"
    local zone="$2"
    local rich_rule

    rich_rule="rule family=\"ipv4\" source address=\"${importer_ip}\" port port=\"${ES_PORT}\" protocol=\"tcp\" accept"

    if firewall-cmd --zone="$zone" --query-rich-rule="$rich_rule" >/dev/null 2>&1; then
        info "firewalld rule already exists in zone '$zone' for ${importer_ip}:tcp/${ES_PORT}"
    else
        firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rich_rule"
        firewall-cmd --reload
        info "Added firewalld rule in zone '$zone': ${importer_ip} -> tcp/${ES_PORT}"
    fi
}

verify_firewalld() {
    local importer_ip="$1"
    local zone="$2"
    local rich_rule

    rich_rule="rule family=\"ipv4\" source address=\"${importer_ip}\" port port=\"${ES_PORT}\" protocol=\"tcp\" accept"
    firewall-cmd --zone="$zone" --query-rich-rule="$rich_rule" >/dev/null 2>&1 \
        || fail "firewalld rule verification failed in zone '$zone'."
}

verify_elasticsearch() {
    local http_code
    http_code="$(curl -sS -o /tmp/sof-elk-es-health.$$ -w '%{http_code}' --max-time 10 "http://127.0.0.1:${ES_PORT}/" || true)"

    if [[ "$http_code" != "200" ]]; then
        rm -f "/tmp/sof-elk-es-health.$$"
        fail "Elasticsearch did not return HTTP 200 on http://127.0.0.1:${ES_PORT}/ (got '${http_code:-no response}'). Check: sudo journalctl -u ${ES_SERVICE} -n 100 --no-pager"
    fi

    rm -f "/tmp/sof-elk-es-health.$$"
    info "Local Elasticsearch API check passed (HTTP 200)."

    if ! ss -lntp 2>/dev/null | grep -Eq "[:.]${ES_PORT}[[:space:]]"; then
        fail "Elasticsearch is not listening on TCP/${ES_PORT}."
    fi

    info "Elasticsearch is listening on TCP/${ES_PORT}."
}

main() {
    require_root

    [[ $# -eq 1 ]] || { usage; exit 2; }

    local importer_ip="$1"
    validate_ipv4 "$importer_ip" || fail "Invalid IPv4 address: '$importer_ip'"

    [[ -f "$ES_CONFIG" ]] || fail "Elasticsearch config not found: $ES_CONFIG"
    command -v firewall-cmd >/dev/null 2>&1 || fail "firewall-cmd was not found. firewalld is required."
    command -v curl >/dev/null 2>&1 || fail "curl is required."
    command -v ss >/dev/null 2>&1 || fail "ss is required."

    info "Importer VM IP: $importer_ip"
    info "Elasticsearch config: $ES_CONFIG"

    if ! firewall-cmd --state >/dev/null 2>&1; then
        fail "firewalld is not running. Start/enable firewalld first."
    fi

    local zone
    zone="$(get_firewalld_zone)" || fail "Could not determine the active firewalld zone."
    info "Using firewalld zone: $zone"

    backup_config

    # Bind Elasticsearch's HTTP/transport services to the host interfaces while
    # explicitly declaring this deployment as a single-node cluster.
    set_yaml_key "network.host" "0.0.0.0"
    set_yaml_key "discovery.type" "single-node"

    info "Configured network.host: 0.0.0.0"
    info "Configured discovery.type: single-node"

    configure_firewalld "$importer_ip" "$zone"
    verify_firewalld "$importer_ip" "$zone"

    info "Restarting Elasticsearch..."
    systemctl restart "$ES_SERVICE"

    # Give the service a reasonable amount of time to come up.
    if ! systemctl is-active --quiet "$ES_SERVICE"; then
        sleep 3
    fi

    systemctl is-active --quiet "$ES_SERVICE" \
        || fail "Elasticsearch failed to start. Check: sudo journalctl -xeu ${ES_SERVICE}.service"

    info "Elasticsearch service is active."
    verify_elasticsearch

    echo
    info "Configuration completed successfully."
    echo
    echo "Next step from the importer VM:"
    echo "  Test-NetConnection $(hostname -I 2>/dev/null | awk '{print $1}') -Port ${ES_PORT}"
    echo "or, if the SOF-ELK node IP is known:"
    echo "  Test-NetConnection <SOF-ELK_IP> -Port ${ES_PORT}"
    echo
    echo "The firewall permits only ${importer_ip} to TCP/${ES_PORT}."
    echo "Elasticsearch is configured as a single-node deployment and listens on all interfaces."
}

main "$@"
