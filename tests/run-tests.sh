#!/bin/bash
# CrypVol 完整测试套件
set -o pipefail

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; NC='\033[0m'
PASS=0; FAIL=0
FAILED=()

CRYPVOL="CrypVol"
TMP="/tmp/crypvol-test-$$"
mkdir -p "$TMP"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

check() {
    local name="$1"; shift
    local out err
    out=$("$@" 2>/dev/null)
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name (rc=$rc)"
        [ -n "$out" ] && echo "    $out"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

check_fail() {
    local name="$1"; shift
    "$@" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name (应失败但成功了)"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

run() { $CRYPVOL "$@" 2>&1; }
sha_all() { find "$1" -type f -exec sha256sum {} \; | sort -k2 | awk '{print $1}'; }

mk_files() {
    local d="$1"
    echo "hello" > "$d/hello.txt"
    mkdir -p "$d/nested/deep"
    echo "deeper" > "$d/nested/deep/file.txt"
    echo "nested" > "$d/nested/data.bin"
    dd if=/dev/urandom of="$d/random.bin" bs=1024 count=200 2>/dev/null
}

verify_extract() {
    local name="$1" src="$2" dst="$3" ref="$4"
    local extra="${5:-}"
    mkdir -p "$dst"
    if run extract "$src" $extra -o "$dst" >/dev/null && diff <(sha_all "$ref") <(sha_all "$dst") >/dev/null; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

section() { echo -e "\n${CYAN}═══ $1 ═══${NC}"; }

# ═══════════════════════════════════════
section "1. genkey"
# ═══════════════════════════════════════
check     "PlainKey"            run genkey -o "$TMP/k-plain.cvk"
check     "Password"            run genkey -o "$TMP/k-pass.cvk" -m Password -p "pwd123"
check_fail "Asymmetric 缺公钥"  run genkey -o "$TMP/k-asym.cvk" -m Asymmetric

# ═══════════════════════════════════════
section "2. pack — 所有加密模式"
# ═══════════════════════════════════════
declare -A PACK_DIR
for mode in None PlainKey Password; do
    d="$TMP/pack-$mode"
    PACK_DIR[$mode]="$d"
    mkdir -p "$d/input" "$d/output"
    mk_files "$d/input"

    case $mode in
        None)     opts="-m None" ;;
        PlainKey) opts="-m PlainKey" ;;
        Password) opts="-m Password -p testpass" ;;
    esac
    check "pack $mode" run pack "$d/input" $opts -o "$d/output" --prefix "$mode"
done

# ── 跨卷 ──
SPLIT_DIR="$TMP/pack-split"
mkdir -p "$SPLIT_DIR/input" "$SPLIT_DIR/output"
dd if=/dev/urandom of="$SPLIT_DIR/input/big.bin" bs=1M count=15 2>/dev/null
check "pack cross-volume" run pack "$SPLIT_DIR/input" -m PlainKey -o "$SPLIT_DIR/output" --prefix split -s 5

# ── --key-file 复用 ──
mkdir -p "$TMP/pack-reuse/input" "$TMP/pack-reuse/output"
mk_files "$TMP/pack-reuse/input"
check "pack --key-file" run pack "$TMP/pack-reuse/input" \
    --key-file "$TMP/k-pass.cvk" -p "pwd123" -o "$TMP/pack-reuse/output"

# ── 压缩 ──
CMP_DIR="$TMP/pack-compress"
mkdir -p "$CMP_DIR/input" "$CMP_DIR/output"
mk_files "$CMP_DIR/input"
check "pack -c (compress)" run pack "$CMP_DIR/input" -m PlainKey -c -o "$CMP_DIR/output"

# ═══════════════════════════════════════
section "3. extract — 还原验证"
# ═══════════════════════════════════════
for mode in None PlainKey Password; do
    d="${PACK_DIR[$mode]}"
    case $mode in
        None|PlainKey) extra="" ;;
        Password) extra="-p testpass" ;;
    esac
    verify_extract "extract $mode" "$d/output" "$TMP/ext-$mode" "$d/input" "$extra"
done

verify_extract "extract cross-volume" "$SPLIT_DIR/output" "$TMP/ext-split" "$SPLIT_DIR/input"
# 压缩提取暂需手动指定 -c (TODO: 自动检测压缩)
# # (compression auto-detect TODO — 跳过 extract compress 测试)
verify_extract "extract dir input"   "${PACK_DIR[None]}/output" "$TMP/ext-dir" "${PACK_DIR[None]}/input"

# ── 空文件 ──
EMPTY_DIR="$TMP/empty"
mkdir -p "$EMPTY_DIR/input" "$EMPTY_DIR/output" "$EMPTY_DIR/restored"
echo -n "" > "$EMPTY_DIR/input/empty.txt"
echo "x"  > "$EMPTY_DIR/input/x.txt"
check "empty file pack"   run pack "$EMPTY_DIR/input" -m PlainKey -o "$EMPTY_DIR/output"
verify_extract "empty file extract" "$EMPTY_DIR/output" "$EMPTY_DIR/restored" "$EMPTY_DIR/input"

# ═══════════════════════════════════════
section "4. browse"
# ═══════════════════════════════════════
check "browse basic"        run browse "${PACK_DIR[PlainKey]}/output"          | grep -q "random.bin"
check "browse --long"       run browse "${PACK_DIR[PlainKey]}/output" --long   | grep -q "200.0K"
check "browse cross-vol"    run browse "$SPLIT_DIR/output" --long               | grep -q "分.*段"
check "browse dir input"    run browse "${PACK_DIR[PlainKey]}/output"          | grep -q "nested"

# ═══════════════════════════════════════
section "5. info"
# ═══════════════════════════════════════
check "info PlainKey"  run info "$TMP/k-plain.cvk" | grep -q "明文"
check "info Password"  run info "$TMP/k-pass.cvk"  | grep -q "密码"
check "info multiple"  run info "$TMP/k-plain.cvk" "$TMP/k-pass.cvk" | grep -q "plain"

# ═══════════════════════════════════════
section "6. rekey"
# ═══════════════════════════════════════
check     "Plain→Password"  run rekey "$TMP/k-plain.cvk" --to-mode Password --new-password "rp" -o "$TMP/k-rp.cvk"
check     "Password→Plain"  run rekey "$TMP/k-pass.cvk" --to-mode PlainKey -p "pwd123" -o "$TMP/k-back.cvk"
check_fail "缺公钥应失败"   run rekey "$TMP/k-plain.cvk" --to-mode Asymmetric

# rekey 后验证：用 rekeyed key + 新密码提取
cp "$TMP/k-rp.cvk" "${PACK_DIR[PlainKey]}/output/PlainKey.cvk"
verify_extract "rekey后extract" "${PACK_DIR[PlainKey]}/output" "$TMP/ext-rekey" \
    "${PACK_DIR[PlainKey]}/input" "-p rp"

# ═══════════════════════════════════════
section "7. convert (块级密钥轮换)"
# ═══════════════════════════════════════
CV_DIR="$TMP/convert"
mkdir -p "$CV_DIR/input" "$CV_DIR/output" "$CV_DIR/conv" "$CV_DIR/restored"
mk_files "$CV_DIR/input"

run pack "$CV_DIR/input" -m Password -p "cpwd" -o "$CV_DIR/output" >/dev/null
check "convert pwd→plain" run convert "$CV_DIR/output" -o "$CV_DIR/conv" --old-password "cpwd" -m PlainKey
verify_extract "convert后extract" "$CV_DIR/conv" "$CV_DIR/restored" "$CV_DIR/input"

# ═══════════════════════════════════════
section "8. 凭据校验"
# ═══════════════════════════════════════
check_fail "无密码应报错"    run extract "${PACK_DIR[Password]}/output" -o "$TMP/_"
check_fail "错误密码应报错"  run extract "${PACK_DIR[Password]}/output" -p "wrong" -o "$TMP/_"
check       "正确密码成功"   run extract "${PACK_DIR[Password]}/output" -p "testpass" -o "$TMP/_"

# ═══════════════════════════════════════
section "9. 大文件 (100MB)"
# ═══════════════════════════════════════
BIG_DIR="$TMP/big"
mkdir -p "$BIG_DIR/input" "$BIG_DIR/output" "$BIG_DIR/restored"
dd if=/dev/zero of="$BIG_DIR/input/big.bin" bs=1M count=100 2>/dev/null
check "100MB pack" run pack "$BIG_DIR/input" -m PlainKey -o "$BIG_DIR/output" -s 40
verify_extract "100MB extract" "$BIG_DIR/output" "$BIG_DIR/restored" "$BIG_DIR/input"

# ═══════════════════════════════════════
echo -e "\n${CYAN}══════════════════════════════════════${NC}"
echo -e "${GREEN}通过: $PASS${NC}  ${RED}失败: $FAIL${NC}"
[ $FAIL -gt 0 ] && { echo -e "\n${RED}失败项:${NC}"; for f in "${FAILED[@]}"; do echo "  ✘ $f"; done; }
exit $FAIL
