#!/usr/bin/env bash
# ZETI UBA — probe ES indices with the es-mcp read-only key.
set -uo pipefail
set -a; source /opt/zeti-uba/mcp/es-mcp/.env; set +a
AUTH="Authorization: ApiKey ${ES_API_KEY}"
U="${ES_URL}"

echo "### uba-* indices (_mapping keys)"
curl -sk -H "$AUTH" "$U/uba-*/_mapping" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if isinstance(d,dict) and 'error' in d:
  print('  ',json.dumps(d)[:200]); sys.exit()
for k in sorted(d): print('  '+k)
"

echo ""
echo "### logs-zeti-* indices (_mapping keys)"
curl -sk -H "$AUTH" "$U/logs-zeti-*/_mapping" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if isinstance(d,dict) and 'error' in d:
  print('  ',json.dumps(d)[:200]); sys.exit()
for k in sorted(d): print('  '+k)
"

cap() {
  curl -sk -H "$AUTH" "$U/$1/_field_caps?fields=*" | python3 -c "
import sys,json
d=json.load(sys.stdin)
f=d.get('fields')
if f is None:
  print('  ',json.dumps(d)[:300]); sys.exit()
for name in sorted(f):
  t='/'.join(sorted(f[name].keys()))
  print('  %s  [%s]' % (name,t))
"
}
sample() {
  curl -sk -H "$AUTH" "$U/$1/_search?size=1" | python3 -c "
import sys,json
d=json.load(sys.stdin)
h=d.get('hits',{}).get('hits',[])
if not h:
  print('  (no docs)'); sys.exit()
print(json.dumps(h[0].get('_source',{}),indent=2,default=str)[:2200])
"
}

for idx in "uba-alerts-*" "uba-risk-scores-*" "uba-intelligence-*" "logs-zeti-*"; do
  echo ""
  echo "==== ${idx} ===="
  curl -sk -H "$AUTH" "$U/$idx/_count" | python3 -c "import sys,json; print('  doc count =', json.load(sys.stdin).get('count','?'))"
  echo "---- field_caps ----"
  cap "$idx"
  echo "---- sample doc ----"
  sample "$idx"
done
