#!/usr/bin/env bash
# ZETI UBA — mint a read-only Elasticsearch API key for the es-mcp server.
#
# Run INTERACTIVELY on the UBA server (i-0e06820c477644613):
#     aws ssm start-session --target i-0e06820c477644613
#     sudo bash /opt/zeti-uba/mcp/es-mcp/mint-es-key.sh
#
# The elastic password is read with `read -s` — it never appears in chat,
# command arguments, shell history, or SSM logs. The minted key is written
# straight into .env on this box; the raw key is never printed.
set -euo pipefail

ES_URL="https://10.0.41.10:9200"
ENV_FILE="/opt/zeti-uba/mcp/es-mcp/.env"

read -rsp "elastic 사용자 비밀번호: " ES_PW
echo

# 1) verify elastic auth
code=$(curl -sk -o /dev/null -w '%{http_code}' -u "elastic:${ES_PW}" "${ES_URL}")
if [ "$code" != "200" ]; then
  echo "ERROR: elastic 인증 실패 (HTTP ${code}). 비밀번호를 확인하세요." >&2
  unset ES_PW
  exit 1
fi
echo "elastic 인증 OK"

# 2) mint a least-privilege (read-only) API key for the es-mcp server
resp=$(curl -sk -u "elastic:${ES_PW}" -X POST "${ES_URL}/_security/api_key" \
  -H 'Content-Type: application/json' -d '{
  "name": "uba-mcp",
  "role_descriptors": {
    "uba_mcp_ro": {
      "cluster": ["monitor"],
      "indices": [
        { "names": ["uba-*", "mitre-attack", "logs-zeti-*"],
          "privileges": ["read", "view_index_metadata"] }
      ]
    }
  },
  "metadata": { "purpose": "zeti-es-mcp read-only", "owner": "uba-server" }
}')
unset ES_PW

encoded=$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("encoded",""))')
key_id=$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))')
if [ -z "$encoded" ]; then
  echo "ERROR: API 키 발급 실패. ES 응답:" >&2
  printf '%s\n' "$resp" >&2
  exit 1
fi

# 3) write .env (owner-only)
umask 077
cat > "$ENV_FILE" <<EOF
ES_URL=${ES_URL}
ES_API_KEY=${encoded}
ES_SSL_VERIFY=false
EOF
chmod 600 "$ENV_FILE"
echo ".env 기록 완료: ${ENV_FILE}  (api_key id=${key_id})"

# 4) verify the new key works
vcode=$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "Authorization: ApiKey ${encoded}" "${ES_URL}/_cat/indices/uba-*?h=index")
echo "신규 키 검증: HTTP ${vcode} (200 기대)"
echo "완료."
