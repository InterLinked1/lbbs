#!/bin/sh

# Perform some basic checks to see if all domains configured for this system are properly set up for email
# Wrapper script around smtp_check_dnsauth_single.sh to find any obvious SMTP/DNS misconfigurations

ENVELOPE_DOMAIN=$( grep "smtp_hostname" /etc/lbbs/net_smtp.conf | cut -d'=' -f2 | cut -d';' -f1 | xargs | tr -d '\r' )
HELO_DOMAIN=$ENVELOPE_DOMAIN
SCRIPT_DIR=$( dirname "$0" )

echo_failure() {
    echo "\033[0;31m$1\033[0m"
}

mod_mail_domains() {
	section=$( awk '/^\[domains/{p=1; print; next} /^\[/{p=0}; p>0{print}' /etc/lbbs/mod_mail.conf )
	echo "$section" | while read -r line; do
		line=$( printf "%s" "$line" | cut -d';' -f1 | xargs | tr -d '\r' ) # Ignore comments
		if [ "$line" = "[domains]" ]; then
			continue # Ignore section name
		fi
		if [ "$line" != "" ]; then
			domain=$( printf "%s" "$line" | cut -d'=' -f1 | xargs )
			echo "$domain"
		fi
	done
}

net_smtp_domains() {
	section=$( awk '/^\[authorized_relays/{p=1; print; next} /^\[/{p=0}; p>0{print}' /etc/lbbs/net_smtp.conf )
	echo "$section" | while read -r line; do
		line=$( printf "%s" "$line" | cut -d';' -f1 | xargs | tr -d '\r' ) # Ignore comments
		if [ "$line" = "[authorized_relays]" ]; then
			continue # Ignore section name
		fi
		if [ "$line" != "" ]; then
			printf "%s\n" "$line" | cut -d'=' -f2 | xargs | tr ',' '\n'
		fi
	done
}

if [ "$ENVELOPE_DOMAIN" = "" ]; then
	echo_failure "No SMTP hostname configured, set 'smtp_hostname' in /etc/lbbs/net_smtp.conf"
	exit 1
fi

printf "%s: %s\n" "Our Public IP Address" "$IP"

# Our domains are in mod_mail.conf, and others for which we can relay/send mail are in net_smtp.conf
MOD_MAIL_DOMAINS=$( mod_mail_domains )
NET_SMTP_DOMAINS=$( net_smtp_domains )
ALL_DOMAINS=$( printf "%s\n" $MOD_MAIL_DOMAINS $NET_SMTP_DOMAINS | sort | uniq )

IP=$( curl --silent https://ip.interlinked.us | tr -d '\r' )
echo "$ALL_DOMAINS" | while read -r FROM_DOMAIN; do
	DKIM_SELECTOR=$( grep "keyfile=" /etc/lbbs/mod_smtp_filter_dkim.conf | grep "/$FROM_DOMAIN/" | rev | cut -d'/' -f1 | rev | cut -d'.' -f1 | tr -d '\r' )
	printf "Checking domain: %s\n" "$FROM_DOMAIN"
	#echo $SCRIPT_DIR/smtp_check_dnsauth_single.sh "$IP" "$ENVELOPE_DOMAIN" "$HELO_DOMAIN" "$FROM_DOMAIN" "$DKIM_SELECTOR"
	$SCRIPT_DIR/smtp_check_dnsauth_single.sh "$IP" "$ENVELOPE_DOMAIN" "$HELO_DOMAIN" "$FROM_DOMAIN" "$DKIM_SELECTOR" | awk '{print "    " $0}'
done
