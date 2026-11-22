#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
root=$PWD
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

bash airgeddon.sh --lab help | grep -q 'Windows support — coming soon'
bash airgeddon.sh --lab tools > "$tmp/tools"
grep -q 'capinfos' "$tmp/tools"
grep -q 'No optional package is made mandatory' "$tmp/tools"
if bash scripts/lab.sh invalid > /dev/null 2>&1; then exit 1; fi
if bash scripts/lab.sh capture > /dev/null 2>&1; then exit 1; fi
if bash scripts/lab.sh wordlist "$tmp/missing" > /dev/null 2>&1; then exit 1; fi
: > "$tmp/empty"
if bash scripts/lab.sh wordlist "$tmp/empty" > /dev/null 2>&1; then exit 1; fi
mkfifo "$tmp/fifo"
if bash scripts/lab.sh wordlist "$tmp/fifo" > /dev/null 2>&1; then exit 1; fi

#Paths with spaces and shell metacharacters remain literal, never executable.
input="$tmp/word list \$(touch SHOULD_NOT_EXIST).txt"
printf '\nshort\npassword123\r\n%s\n' "$(printf '%064d' 0)" > "$input"
before=$(sha256sum -- "$input")
bash scripts/lab.sh wordlist "$input" > "$tmp/statistics"
[[ $(sha256sum -- "$input") = "$before" ]]
grep -q 'Entries: 4' "$tmp/statistics"
grep -q 'Empty entries: 1' "$tmp/statistics"
grep -q '8–63 byte candidates: 1' "$tmp/statistics"
grep -q '64-character hex candidates: 1' "$tmp/statistics"
if grep -q password123 "$tmp/statistics"; then
	echo 'Wordlist contents leaked into statistics.'; exit 1
fi
[[ ! -e SHOULD_NOT_EXIST ]]

#Mock metadata inspection: validate argv preservation and failure propagation.
mkdir "$tmp/bin"
cat > "$tmp/bin/capinfos" <<'MOCK'
#!/usr/bin/env bash
[[ $# = 5 && $1 = -c && $2 = -s && $3 = -a && $4 = -e && $5 = "$EXPECTED_INPUT" ]] || exit 2
exit "${MOCK_STATUS:-0}"
MOCK
chmod +x "$tmp/bin/capinfos"
export EXPECTED_INPUT="$input"
PATH="$tmp/bin:$PATH" bash "$root/scripts/lab.sh" capture "$input" > /dev/null
if MOCK_STATUS=1 PATH="$tmp/bin:$PATH" bash scripts/lab.sh capture "$input" > /dev/null 2>&1; then
	echo 'Metadata failure was not reported.'; exit 1
fi
[[ $(sha256sum -- "$input") = "$before" ]]
#Read-only CLI works independently of the caller working directory.
(cd "$tmp" && bash "$root/airgeddon.sh" --lab help > /dev/null)
printf '%s\n' 'PASS: lab CLI, literal filenames, read-only statistics and metadata failure handling'
