#!/bin/sh

# Emulate DNS-based authentication tests for a sent email as processed by another receiving mail server
# This is not a comprehensive check of all SMTP/DNS configuration, but can be used to find obvious major issues

# $1 = Public IP address of the mail server
# $2 = Envelope sender domain (MAIL FROM domain)
# $3 = HELO/EHLO domain when sending mail
# $4 = From domain (From header domain)
# $5 = DKIM selector name, default=default

echo_success() {
    printf "\033[0;32m$1\033[0m\n"
}

echo_failure() {
    printf "\033[0;31m$1\033[0m\n"
}

if [ $# -lt 4 ] || [ $# -gt 5 ]; then
    printf "Usage: $0 <IP_ADDRESS> <ENVELOPE_DOMAIN> <HELO_DOMAIN> <FROM_DOMAIN> [DKIM_SELECTOR]\n"
    exit 22
fi

IP="$1"
ENVELOPE_DOMAIN="$2"
HELO_DOMAIN="$3"
FROM_DOMAIN="$4"
DKIM_SELECTOR="${5:-default}" # Use 'default' if not provided
EXIT_CODE=0

if [ "$IP" = "" ]; then
	echo_failure "IP address cannot be empty"
	exit 22
fi
if [ "$ENVELOPE_DOMAIN" = "" ]; then
	echo_failure "Envelope sender domain cannot be empty"
	exit 22
fi
if [ "$HELO_DOMAIN" = "" ]; then
	echo_failure "HELO domain cannot be empty"
	exit 22
fi
if [ "$FROM_DOMAIN" = "" ]; then
	echo_failure "From header domain cannot be empty"
	exit 22
fi

# SPF check
if ! which "spfquery" > /dev/null; then
	apt-get install spfquery
fi
spf_result=$(spfquery -ip "$IP" -sender "postmaster@$ENVELOPE_DOMAIN" -helo "$ENVELOPE_DOMAIN" 2>/dev/null)
if echo "$spf_result" | grep -q "pass"; then
	echo_success "SPF check passed: IP $IP is authorized for envelope sender domain ($ENVELOPE_DOMAIN)"
else
	echo_failure "SPF check failed: IP $IP is NOT authorized for envelope sender domain ($ENVELOPE_DOMAIN)"
	EXIT_CODE=1
fi

# DKIM check
if ! which "dig" > /dev/null; then
	apt-get install dnsutils
fi
dkim_domain="$DKIM_SELECTOR._domainkey.$FROM_DOMAIN"
dkim_record=$(dig +short TXT "$dkim_domain")
if echo "$dkim_record" | grep -q "v=DKIM1"; then
    echo_success "DKIM record found for selector '$DKIM_SELECTOR' under From domain ($FROM_DOMAIN)"
else
    echo_failure "DKIM record missing for selector '$DKIM_SELECTOR' under From domain ($FROM_DOMAIN)"
    EXIT_CODE=1
fi

# DMARC check
dmarc_domain="_dmarc.$FROM_DOMAIN"
dmarc_record=$(dig +short TXT "$dmarc_domain")
if echo "$dmarc_record" | grep -q "v=DMARC1"; then
    if echo "$dmarc_record" | grep -Eq "p=(quarantine|reject)"; then
        echo_success "DMARC policy is enforcing: $(echo "$dmarc_record" | grep -o "p=[^;]*")"
    else
        echo_failure "DMARC policy is not enforcing (p=none)."
        EXIT_CODE=1
    fi
else
    echo_failure "DMARC record missing for From domain."
    EXIT_CODE=1
fi

# Forward-confirmed reverse DNS check (FCrDNS)
ptr_hostname=$(dig +short -x "$IP" | sed 's/\.$//')
resolved_ips=$(dig +short "$ptr_hostname" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
if echo "$resolved_ips" | grep -q "^$IP$"; then
	if [ "$ptr_hostname" = "$HELO_DOMAIN" ]; then
		echo_success "FCrDNS check passed: $IP <-> $HELO_DOMAIN <-> $ptr_hostname"
	else
		echo_failure "FCrDNS check failed: $HELO_DOMAIN != $ptr_hostname"
	fi
else
    echo_failure "FCrDNS check failed: $ptr_hostname does not resolve back to $IP"
    EXIT_CODE=1
fi

# MX record check
mx_record=$(dig +short MX "$ENVELOPE_DOMAIN")
if [ -n "$mx_record" ]; then
    echo_success "MX record found for envelope sender domain ($ENVELOPE_DOMAIN)."
else
    echo_failure "MX record missing for envelope sender domain ($ENVELOPE_DOMAIN)."
    EXIT_CODE=1
fi

exit $EXIT_CODE
