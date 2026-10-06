#!/bin/sh
# 검증용 평문 NTFS 볼륨(합성 Claude Desktop 아티팩트)을 만든다.
#
#   wsl -u root -- sh tests/make_ntfs_fixture.sh <출력.img>
#
# WSL(또는 리눅스)의 ntfs-3g 가 필요하다 (apt-get install ntfs-3g).
# 결과는 tests/_data/claude_ntfs.img.gz 로 저장소에 들어 있으므로 평소에는 다시
# 만들 필요가 없다. 내용은 전부 손으로 쓴 가짜 값이다 (실제 대화·계정 없음).
set -eu
OUT="$1"
MNT=$(mktemp -d)
rm -f "$OUT"
truncate -s 32M "$OUT"
mkntfs -F -Q -q -s 512 -c 4096 -L CLAUDETEST "$OUT"
ntfs-3g -o loop "$OUT" "$MNT"

LOG="$MNT/Users/tester/AppData/Local/Claude/logs"
CFG="$MNT/Users/tester/AppData/Roaming/Claude"
CLI="$MNT/Users/tester/.claude"
mkdir -p "$LOG" "$CFG" "$CLI"

# 앱 로그는 시간대 없는 현지시각(KST)이다. 파일 수정시각(UTC)과 마지막 줄로 +9 를 추정한다.
cat > "$LOG/main.log" <<'EOF'
2026-09-23 13:03:58 [info] Starting Claude
2026-09-23 13:04:10 [info] Login-state transition: loggedOut: true -> false uuid: <none> -> 11111111-2222-4333-8444-555555555555
2026-09-23 13:20:00 [info] some unrelated line
2026-09-23 13:24:51 [info] beforeQuit
EOF
touch -d "2026-09-23 04:24:51 UTC" "$LOG/main.log"

cat > "$CFG/config.json" <<'EOF'
{"locale": "ko-KR", "userThemeMode": "system"}
EOF
touch -d "2026-09-23 04:24:50 UTC" "$CFG/config.json"

# 이름만 겹치는 다른 제품(Claude Code CLI) — 결과에 실리면 안 된다
echo '{"theme":"dark"}' > "$CLI/settings.json"

sync
umount "$MNT"
rmdir "$MNT"
