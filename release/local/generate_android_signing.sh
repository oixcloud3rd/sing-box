#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd "$(dirname "$0")/../.." && pwd)"
signing_dir="${project_dir}/.signing/android"
keystore_path="${signing_dir}/release.keystore"
properties_path="${signing_dir}/local.properties"
keystore_secret_path="${signing_dir}/ANDROID_KEYSTORE_BASE64.txt"
properties_secret_path="${signing_dir}/LOCAL_PROPERTIES.txt"
key_alias="oixcloud"

if [[ -e "${keystore_path}" || -e "${properties_path}" ]]; then
  echo "Android signing material already exists in ${signing_dir}" >&2
  echo "Move or remove it explicitly before generating a new signing identity." >&2
  exit 1
fi

umask 077
mkdir -p "${signing_dir}"

keystore_password="$(openssl rand -hex 24)"

keytool -genkeypair \
  -keystore "${keystore_path}" \
  -storetype PKCS12 \
  -storepass "${keystore_password}" \
  -keypass "${keystore_password}" \
  -alias "${key_alias}" \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000 \
  -dname "CN=oixcloud3rd, O=oixcloud3rd, C=CN"

printf 'KEYSTORE_PASS=%s\nALIAS_NAME=%s\nALIAS_PASS=%s\n' \
  "${keystore_password}" \
  "${key_alias}" \
  "${keystore_password}" > "${properties_path}"

base64 < "${keystore_path}" | tr -d '\n' > "${keystore_secret_path}"
base64 < "${properties_path}" | tr -d '\n' > "${properties_secret_path}"

chmod 600 \
  "${keystore_path}" \
  "${properties_path}" \
  "${keystore_secret_path}" \
  "${properties_secret_path}"

echo "Generated a new Android signing identity in ${signing_dir}"
echo "Back up release.keystore and local.properties in a secure location."
echo "Use ANDROID_KEYSTORE_BASE64.txt and LOCAL_PROPERTIES.txt as GitHub Secret values."
