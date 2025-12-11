#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8080}"
ADMIN_EMAIL="admin@cmu.edu"
ADMIN_PASS="secret123"

# Make a fresh student each run so we can see points move in real time
RAND=$(( RANDOM % 9000 + 1000 ))
STU_EMAIL="eco${RAND}@cmu.edu"
STU_PASS="secret123"

json() { jq -r "$1"; }
hr() { printf "\n==== %s ====\n" "$1"; }

# ---------------------------
# 0) Health
# ---------------------------
hr "Health"
curl -fsS "$API/healthz" && echo " OK"

# ---------------------------
# 1) Register/login admin
# ---------------------------
hr "Register admin (idempotent)"
set +e
curl -fsS -o /dev/null -w "%{http_code}\n" -X POST "$API/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"'"$ADMIN_EMAIL"'","username":"admin","password":"'"$ADMIN_PASS"'","base_role":"staff","is_admin":true}'
set -e

hr "Login admin"
ADMIN_TOKEN=$(
  curl -fsS -X POST "$API/v1/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"'"$ADMIN_EMAIL"'","password":"'"$ADMIN_PASS"'"}' \
  | json '.access_token'
)
echo "ADMIN_TOKEN: ${#ADMIN_TOKEN} chars"

# ---------------------------
# 2) Register/login student
# ---------------------------
hr "Register student (fresh)"
curl -fsS -X POST "$API/v1/auth/register" -H "Content-Type: application/json" \
  -d '{"email":"'"$STU_EMAIL"'","username":"eco-user-'$RAND'","password":"'"$STU_PASS"'","base_role":"student","is_admin":false}' \
  | jq

hr "Login student"
STU_TOKEN=$(
  curl -fsS -X POST "$API/v1/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"'"$STU_EMAIL"'","password":"'"$STU_PASS"'"}' \
  | json '.access_token'
)
echo "STU_TOKEN: ${#STU_TOKEN} chars"

# ---------------------------
# 3) /me baseline (0 points, 0 bonus)
# ---------------------------
hr "Baseline /v1/me"
curl -fsS "$API/v1/me" -H "Authorization: Bearer $STU_TOKEN" | jq

# ---------------------------
# 4) Admin creates 30-pt event; student attends (award 30, overflow 0)
# ---------------------------
hr "Create 30-pt event"
EV1_ID=$(
  curl -fsS -X POST "$API/v1/admin/events" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"title":"Beach Cleanup","description":"Bring gloves",
         "starts_at":"'$(date -u -v+1H +"%Y-%m-%dT%H:%M:%SZ")'",
         "ends_at":"'$(date -u -v+2H +"%Y-%m-%dT%H:%M:%SZ")'",
         "location":"CMUQ","points":30,"category":"environment"}' \
  | json '.id'
)
echo "EV1_ID=$EV1_ID"

hr "QR wire (json) for EV1"
WIRE1=$(curl -fsS "$API/v1/admin/events/$EV1_ID/qr?format=json" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$WIRE1" | jq

hr "Attend EV1"
curl -fsS -X POST "$API/v1/scan/attend" \
  -H "Authorization: Bearer $STU_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$WIRE1" | jq

# ---------------------------
# 5) Duplicate attend blocked
# ---------------------------
hr "Duplicate attend EV1 (should be duplicate:true)"
curl -fsS -X POST "$API/v1/scan/attend" \
  -H "Authorization: Bearer $STU_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$WIRE1" | jq

# ---------------------------
# 6) Create 25-pt event; student attends (hits cap 50 → award 20, overflow 5)
# ---------------------------
hr "Create 25-pt event"
EV2_ID=$(
  curl -fsS -X POST "$API/v1/admin/events" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"title":"Tree Planting",
         "starts_at":"'$(date -u -v+3H +"%Y-%m-%dT%H:%M:%SZ")'",
         "ends_at":"'$(date -u -v+4H +"%Y-%m-%dT%H:%M:%SZ")'",
         "location":"CMUQ","points":25,"category":"environment"}' \
  | json '.id'
)
echo "EV2_ID=$EV2_ID"

hr "QR wire (json) for EV2"
WIRE2=$(curl -fsS "$API/v1/admin/events/$EV2_ID/qr?format=json" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$WIRE2" | jq

hr "Attend EV2 (expect award 20, overflow_bonus 5)"
curl -fsS -X POST "$API/v1/scan/attend" \
  -H "Authorization: Bearer $STU_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$WIRE2" | jq

# ---------------------------
# 7) At cap; create 10-pt event; award 0, overflow 10
# ---------------------------
hr "Create 10-pt event (test overflow at cap)"
EV3_ID=$(
  curl -fsS -X POST "$API/v1/admin/events" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"title":"Small Drive",
         "starts_at":"'$(date -u -v+5H +"%Y-%m-%dT%H:%M:%SZ")'",
         "ends_at":"'$(date -u -v+6H +"%Y-%m-%dT%H:%M:%SZ")'",
         "location":"CMUQ","points":10,"category":"environment"}' \
  | json '.id'
)
echo "EV3_ID=$EV3_ID"

hr "QR wire (json) for EV3"
WIRE3=$(curl -fsS "$API/v1/admin/events/$EV3_ID/qr?format=json" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$WIRE3" | jq

hr "Attend EV3 (expect award 0, overflow_bonus 10, capped true)"
curl -fsS -X POST "$API/v1/scan/attend" \
  -H "Authorization: Bearer $STU_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$WIRE3" | jq

# ---------------------------
# 8) Check /me totals (year_points=50, bonus_year >= 15)
# ---------------------------
hr "Check /v1/me totals"
curl -fsS "$API/v1/me" -H "Authorization: Bearer $STU_TOKEN" | jq '.totals'

# ---------------------------
# 9) Badges and ledgers
# ---------------------------
hr "My badges (should include Y1_50 after hitting 50)"
curl -fsS "$API/v1/me/badges" -H "Authorization: Bearer $STU_TOKEN" | jq

hr "My counted ledger (points)"
curl -fsS "$API/v1/me/ledger" -H "Authorization: Bearer $STU_TOKEN" | jq

hr "My bonus ledger (overflow entries)"
curl -fsS "$API/v1/me/bonus" -H "Authorization: Bearer $STU_TOKEN" | jq

# ---------------------------
# 10) Tamper test (bad signature)
# ---------------------------
hr "Tamper QR signature (expect 400 bad signature)"
BAD_SIG=$(echo -n "bad" | base64 -w 0 2>/dev/null || echo -n "bad" | base64)
TAMPER=$(echo "$WIRE1" | jq --arg s "$BAD_SIG" '.signature=$s')
set +e
RESP=$(curl -s -o /dev/stderr -w "%{http_code}" -X POST "$API/v1/scan/attend" \
  -H "Authorization: Bearer $STU_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$TAMPER")
set -e
echo "HTTP $RESP"


echo "== Register (idempotent) and login admin =="
curl -s -X POST $API/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"'"$ADMIN_EMAIL"'","username":"admin","password":"'"$ADMIN_PASS"'","base_role":"staff","is_admin":true}' >/dev/null || true

ADMIN_TOKEN=$(curl -s -X POST $API/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"'"$ADMIN_EMAIL"'","password":"'"$ADMIN_PASS"'"}' | jq -r .access_token)
echo "Admin token len: ${#ADMIN_TOKEN}"

echo "== Create a future event (points=60) =="
EV_ID=$(curl -s -X POST $API/v1/admin/events \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Beach Cleanup","description":"Bring gloves",
       "starts_at":"2099-01-01T10:00:00Z",
       "ends_at":"2099-01-01T12:00:00Z",
       "location":"CMUQ","points":60,"category":"environment"}' | jq -r .id)
echo "Event ID: $EV_ID"

echo "== Get QR wire (JSON payload for scanner) =="
WIRE=$(curl -s "$API/v1/admin/events/$EV_ID/qr?format=json" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$WIRE" | jq .

echo "== Register + login a fresh student (${STU_EMAIL}) =="
curl -s -X POST $API/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"'"$STU_EMAIL"'","username":"eco-user-'$RAND'","password":"'"$STU_PASS"'","base_role":"student","is_admin":false}' >/dev/null

STU_TOKEN=$(curl -s -X POST $API/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"'"$STU_EMAIL"'","password":"'"$STU_PASS"'"}' | jq -r .access_token)
echo "Student token len: ${#STU_TOKEN}"

echo "== Student attends via /v1/scan/attend (should award up to cap, overflow to bonus) =="
curl -s -X POST $API/v1/scan/attend \
  -H "Authorization: Bearer $STU_TOKEN" -H 'Content-Type: application/json' \
  -d "$WIRE" | jq .

echo "== Admin event stats =="
curl -s "$API/v1/admin/events/$EV_ID/stats" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

echo "== Admin event attendees (first 50) =="
curl -s "$API/v1/admin/events/$EV_ID/attendees?limit=50" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

echo
echo "✅ Done. Student: $STU_EMAIL"
