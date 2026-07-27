#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ID="${FIREBASE_PROJECT_ID:-share-browser-7091c}"
INSTANCE_NAME="${PROJECT_ID}-default-rtdb"
SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

heading() {
  printf '\n\033[1;36m%s\033[0m\n' "$1"
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

command -v node >/dev/null || die "Node.js is required."
command -v npm >/dev/null || die "npm is required."

cd "$SETUP_DIR"

heading "1/8 Installing API and setup tools"
npm install

heading "2/8 Reading the Firebase service-account key"
printf '%s\n' \
  "Firebase Console -> Project settings -> Service accounts -> Generate new private key"

SERVICE_ACCOUNT_PATH=""
while IFS= read -r candidate; do
  SERVICE_ACCOUNT_PATH="$candidate"
  break
done < <(
  find "$SETUP_DIR" -maxdepth 1 -type f \
    \( -name '*-firebase-adminsdk-*.json' -o -name 'service-account*.json' \) \
    -print
)

if [[ -n "$SERVICE_ACCOUNT_PATH" ]]; then
  printf 'Detected service-account file: %s\n' "$SERVICE_ACCOUNT_PATH"
else
  read -r -p "Path to the downloaded service-account JSON file: " SERVICE_ACCOUNT_PATH
fi

[[ -f "$SERVICE_ACCOUNT_PATH" ]] || die "Service-account file was not found."
export GOOGLE_APPLICATION_CREDENTIALS="$(realpath "$SERVICE_ACCOUNT_PATH")"

SERVICE_VALUES="$(node - "$SERVICE_ACCOUNT_PATH" <<'NODE'
const fs = require("fs");
const path = process.argv[2];
const data = JSON.parse(fs.readFileSync(path, "utf8"));
for (const key of ["project_id", "client_email", "private_key"]) {
  if (!data[key]) throw new Error(`Service-account JSON is missing ${key}`);
}
process.stdout.write(JSON.stringify({
  projectId: data.project_id,
  clientEmail: data.client_email,
  privateKey: data.private_key
}));
NODE
)"

SERVICE_PROJECT_ID="$(node -e \
  'const d=JSON.parse(process.argv[1]);process.stdout.write(d.projectId)' \
  "$SERVICE_VALUES")"
CLIENT_EMAIL="$(node -e \
  'const d=JSON.parse(process.argv[1]);process.stdout.write(d.clientEmail)' \
  "$SERVICE_VALUES")"
PRIVATE_KEY="$(node -e \
  'const d=JSON.parse(process.argv[1]);process.stdout.write(d.privateKey)' \
  "$SERVICE_VALUES")"

[[ "$SERVICE_PROJECT_ID" == "$PROJECT_ID" ]] ||
  die "The service-account key belongs to $SERVICE_PROJECT_ID, not $PROJECT_ID."

heading "3/8 Checking Realtime Database"
DATABASE_LIST="$(npx --yes firebase-tools database:instances:list \
  --project "$PROJECT_ID" --json 2>/dev/null || printf '{"result":[]}' )"

if ! printf '%s' "$DATABASE_LIST" | grep -q "$INSTANCE_NAME"; then
  printf 'No default Realtime Database was detected for %s.\n' "$PROJECT_ID"
  printf '%s\n' \
    "Create it in Firebase Console, then run this script again."
  die "Realtime Database is not configured."
fi

DEFAULT_DATABASE_URL="https://${INSTANCE_NAME}.firebaseio.com"
read -r -p \
  "Realtime Database URL (press Enter for ${DEFAULT_DATABASE_URL}): " \
  DATABASE_URL
DATABASE_URL="${DATABASE_URL:-$DEFAULT_DATABASE_URL}"
[[ "$DATABASE_URL" == https://* ]] ||
  die "The database URL must start with https://"

heading "4/8 Deploying locked database rules"
npx --yes firebase-tools deploy --only database \
  --project "$PROJECT_ID" --config firebase.setup.json

heading "5/8 Generating API security values"
PIN_PEPPER="$(node -e \
  'process.stdout.write(require("crypto").randomBytes(48).toString("base64url"))')"
SESSION_PEPPER="$(node -e \
  'process.stdout.write(require("crypto").randomBytes(48).toString("base64url"))')"
RECOVERY_PEPPER="$(node -e \
  'process.stdout.write(require("crypto").randomBytes(48).toString("base64url"))')"
ADMIN_SECRET="$(node -e \
  'process.stdout.write(require("crypto").randomBytes(48).toString("base64url"))')"

read -r -p \
  "Reward redirect URL (press Enter for https://omg10.com/4/11435374): " \
  REDIRECT_URL
REDIRECT_URL="${REDIRECT_URL:-https://omg10.com/4/11435374}"

heading "6/8 Linking this folder to the Vercel API project"
npx --yes vercel link

set_vercel_env() {
  local name="$1"
  local value="$2"
  local sensitivity="${3:-normal}"
  local flags=(env add "$name" production --force)
  if [[ "$sensitivity" == "sensitive" ]]; then
    flags+=(--sensitive)
  fi
  printf '%s' "$value" | npx --yes vercel "${flags[@]}" >/dev/null
  printf 'Configured %s\n' "$name"
}

heading "7/8 Configuring private Vercel environment variables"
set_vercel_env FIREBASE_PROJECT_ID "$PROJECT_ID"
set_vercel_env FIREBASE_DATABASE_URL "$DATABASE_URL"
set_vercel_env FIREBASE_CLIENT_EMAIL "$CLIENT_EMAIL" sensitive
set_vercel_env FIREBASE_PRIVATE_KEY "$PRIVATE_KEY" sensitive
set_vercel_env PIN_PEPPER "$PIN_PEPPER" sensitive
set_vercel_env SESSION_PEPPER "$SESSION_PEPPER" sensitive
set_vercel_env RECOVERY_PEPPER "$RECOVERY_PEPPER" sensitive
set_vercel_env ADMIN_SECRET "$ADMIN_SECRET" sensitive
set_vercel_env REDIRECT_TARGET_URL "$REDIRECT_URL"

heading "8/8 Deploying the API"
npx --yes vercel --prod

printf '\nSetup complete.\n'
printf 'Test: https://api.scriptnovaa.com/api/health\n'
printf '%s\n' \
  'Expected: {"ok":true,"product":"Share Browser API","database":"Firebase Realtime Database"}'
printf '\nDelete the service-account JSON after confirming the API works.\n'
