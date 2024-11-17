#!/bin/sh

# OAuth interactive helper script

# This script automates/assists the partly manual steps involved in getting OAuth tokens for email accounts.

#### MANUAL STEPS ####
# (Mostly for reference, the script does many of these things for you automatically)

### Instructions for Gmail ###
# Helpful Resource: https://github.com/google/gmail-oauth2-tools/wiki/OAuth2DotPyRunThrough
# Create your own application using these steps: https://github.com/simonrob/email-oauth2-proxy#oauth-20-client-credentials
# While you could technically use the client ID/secret application baked into an open source application (e.g. Thunderbird),
# this is not recommended; you should register your own OAuth client ID/secret that you can use, so you can troubleshoot.
# 1. For Gmail, register a Web application instead of a Desktop application, and then add
# http://localhost as an allowed Redirect URI.
# Also fill out all the information or you may get a cryptic error, because Google thinks it's a spammy request.
# For Gmail, there are 2 steps: first, you need to get the authorization code,
# and then you need to use that to get the tokens (including the refresh token).
# 2. After you've created an OAuth web application as online guides will walk you through,
# visit the following URL (substitute first):
# https://accounts.google.com/o/oauth2/auth?client_id=CLIENTID&redirect_uri=http://localhost&response_type=code&scope=https%3A%2F%2Fmail.google.com%2F&access_type=offline&prompt=consent
# 3. Once you grant access to your account, Google will redirect to a page on localhost (that probably won't load anything).
#    However, the redirected URL will contain a code in the URL. Copy this code.
#    Note that this a one-time code. If you mess up on a later step, you'll need to repeat this step and get a new authorization code.
#
# 4. To get the actual tokens from the authorization code, run this curl command (substitute first):
# curl --request POST --data "code=AUTHCODE&client_id=CLIENTID&client_secret=CLIENTSECRET&redirect_uri=http://localhost&grant_type=authorization_code" https://oauth2.googleapis.com/token
#
# 5. If everything worked, you should get a JSON response that contains both an access token and a refresh token.
#    The access token is what actually grants access and is good for an hour.
#    The refresh token is persistent and can be used to obtain new access tokens in the future.
#    For this config, we want the refresh token since that won't change, and will enable the BBS to get new access tokens on your behalf.
#    For example, the following curl command will get a new access token using your refresh token:
# curl --request POST --data "client_id=CLIENTID&client_secret=CLIENTSECRET&grant_type=refresh_token&refresh_token=REFRESH TOKEN" https://oauth2.googleapis.com/token
#    The response is similar to the auth code -> token request, except only an access token is returned, not another refresh token.

### Instructions for Microsoft / Office365 ###
# Documentation: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
#                https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
#
# Note: This example reuses the Thunderbird client ID since Microsoft makes it difficult/impossible to get an OAuth2 client ID without an Azure subscription:
# https://github.com/mozilla/releases-comm-central/blob/5719cc261449da589801bd1f1b980d1a9ee7e7df/mailnews/base/src/OAuth2Providers.sys.mjs#L139
# Use at your own risk.
#
# Unlike Gmail, no client secret is used for Microsoft accounts.
#
# The following instructions apply to Microsoft accounts:
# 1. Visit the following URL in a private browser window:
# https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&response_type=code&redirect_uri=https://localhost&response_mode=query&scope=https://outlook.office.com/IMAP.AccessAsUser.All%20https://outlook.office.com/POP.AccessAsUser.All%20https://outlook.office.com/SMTP.Send%20offline_access
# 2. Log in and then capture the code query parameter on the redirect page.
# 3. Run the following curl command (substitute CODE with the code from step 2):
# curl --request POST --data "client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&scope=https://graph.microsoft.com/mail.read&code=CODE&redirect_uri=https://localhost&grant_type=authorization_code" https://login.microsoftonline.com/common/oauth2/v2.0/token
# 4. If everything worked, you should get a JSON response that contains an access token and a refresh token.
# 5. As an example, to get a new access token using your refresh token (substituting appropriately):
# curl --request POST --data 'client_id=9e5f94bc-e8a4-4e73-b8be-63364c29d753&grant_type=refresh_token&refresh_token=REFRESH-TOKEN' https://login.microsoftonline.com/common/oauth2/v2.0/token

AUTH_URL=""
TOKEN_URL=""

PROVIDER=""
CLIENT_ID=""
CLIENT_SECRET=""
AUTH_CODE=""
REDIRECT_URL=""
ACCESS_TOKEN=""
REFRESH_TOKEN=""

USERNAME=""
IMAP_SERVER=""

printf "%s\n" "--- OAuth2 token helper ---"
printf "Select an option, then press ENTER:\n"
printf "g) Get tokens for Google account\n"
printf "m) Get tokens for Microsoft account\n"
printf "0) Provide an access token and get the base64-encoded XOAUTH2 string\n"
printf "a) Log in to IMAP server using XOAUTH2 string\n"
printf "Option: "

calculate_xoauth2() {
	if [ "$USERNAME" = "" ]; then
		printf "Username: "
		read -r USERNAME
	fi
	if [ "$ACCESS_TOKEN" = "" ]; then
		printf "Access token: "
		read -r ACCESS_TOKEN
	fi
	# user=%s%cauth=Bearer %s%c%c, where %c is x01 and %s is the access token
	hex01=$( printf '%02X' 1 | xxd -r -p ) # 0x01
	XOAUTH2_ENCODED=$( printf "user=%s%sauth=Bearer %s%s%s" "$USERNAME" "$hex01" "$ACCESS_TOKEN" "$hex01" "$hex01" | base64 | tr -d '\n' )
	printf "Encoded: %s\n\n" "$XOAUTH2_ENCODED"
}

server_connect() {
	printf "Connecting to %s:%d\n" $IMAP_SERVER 993
	# Since we are piping to openssl s_client, it will handle the LF to CR LF conversions for us
	sh -c "echo \"a1 AUTHENTICATE XOAUTH2 $XOAUTH2_ENCODED\" && cat" | openssl s_client -quiet -connect $IMAP_SERVER:993 -crlf
}

read -r opt
if [ "$opt" = "g" ]; then
	printf "Google OAuth2 token generator\n"
	PROVIDER="google"
	CLIENT_ID="406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com"
	CLIENT_SECRET="kSmqreRr0qwBWJgbf5Y-PjSU"
	REDIRECT_URL="http://localhost"
	AUTH_URL="https://accounts.google.com/o/oauth2/auth?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URL&response_type=code&scope=https%3A%2F%2Fmail.google.com%2F&access_type=offline&prompt=consent"
	TOKEN_URL="https://oauth2.googleapis.com/token"
	IMAP_SERVER="imap.gmail.com"
elif [ "$opt" = "m" ]; then
	printf "Microsoft OAuth2 token generator\n"
	PROVIDER="microsoft"
	CLIENT_ID="9e5f94bc-e8a4-4e73-b8be-63364c29d753"
	REDIRECT_URL="https://localhost"
	AUTH_URL="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=$CLIENT_ID&response_type=code&redirect_uri=$REDIRECT_URL&response_mode=query&scope=https://outlook.office.com/IMAP.AccessAsUser.All%20https://outlook.office.com/POP.AccessAsUser.All%20https://outlook.office.com/SMTP.Send%20offline_access"
	TOKEN_URL="https://login.microsoftonline.com/common/oauth2/v2.0/token"
	IMAP_SERVER="outlook.office365.com"
elif [ "$opt" = "0" ]; then
	calculate_xoauth2
	exit
elif [ "$opt" = "a" ]; then
	printf "g) Google IMAP\n"
	printf "m) Microsoft IMAP\n"
	printf "Option: "
	read -r opt
	if [ "$opt" = "g" ]; then
		IMAP_SERVER="imap.gmail.com"
	elif [ "$opt" = "m" ]; then
		IMAP_SERVER="outlook.office365.com"
	else
		printf "Invalid option\n"
		exit 1
	fi
	calculate_xoauth2
	server_connect
	exit
else
	printf "Invalid option!\n"
	exit 1
fi

while [ "$AUTH_CODE" = "" ]; do
	printf "Visit the following URL in your browser: %s\n\n" "$AUTH_URL"
	printf "Sign in, then copy and paste the code after the '&code=' query parameter: "
	read -r AUTH_CODE

	# Exchange the code we got for the JSON response containing the tokens
	if [ "$REFRESH_TOKEN" = "" ]; then
		json=$( curl --silent --request POST --data "code=$AUTH_CODE&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=$REDIRECT_URL&grant_type=authorization_code" $TOKEN_URL )
		printf "\n$json\n\n"
		printf "$json" | grep "error" > /dev/null
		if [ $? -eq 0 ]; then
			AUTH_CODE="" # Auth code was invalid
			continue
		fi
		EXPIRES_IN=$( printf "$json" | jq -r '.expires_in' )
		ACCESS_TOKEN=$( printf "$json" | jq -r '.access_token' )
		REFRESH_TOKEN=$( printf "$json" | jq -r '.refresh_token' )
		if [ "$EXPIRES_IN" = "null" ]; then
			EXPIRES_IN=""
			ACCESS_TOKEN=""
			REFRESH_TOKEN=""
		fi
	fi
done

while true; do
	printf "Expires In:    %s\n\n" "$EXPIRES_IN"
	printf "Access Token:  %s\n\n" "$ACCESS_TOKEN"
	printf "Refresh Token: %s\n\n" "$REFRESH_TOKEN"

	printf "Select an option, then press ENTER:\n"
	printf "a) Log in to IMAP server\n"
	printf "r) Refresh tokens\n"
	printf "Option: "
	read -r opt

	if [ "$opt" = "r" ]; then
		json=$( curl --silent --request POST --data "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=refresh_token&refresh_token=$REFRESH_TOKEN" $TOKEN_URL )
		printf "\n$json\n\n"
		EXPIRES_IN=$( printf "$json" | jq -r '.expires_in' )
		ACCESS_TOKEN=$( printf "$json" | jq -r '.access_token' )
		REFRESH_TOKEN=$( printf "$json" | jq -r '.refresh_token' )
		# Will loop again and print out the new tokens
	elif [ "$opt" = "a" ]; then
		calculate_xoauth2
		if [ "$IMAP_SERVER" != "" ]; then
			server_connect
		fi
		exit
	fi
done
