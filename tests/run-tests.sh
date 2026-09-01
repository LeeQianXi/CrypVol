#!/bin/bash
# CrypVol 完整测试套件
set -o pipefail

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; NC='\033[0m'
PASS=0; FAIL=0; SKIP=0
FAILED=()

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_DLL="$ROOT_DIR/CrypVol.Cli/bin/Release/net10.0/CrypVol.dll"
TMP="/tmp/crypvol-test-$$"
mkdir -p "$TMP"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# 可通过 CRYPVOL_BIN 覆盖为已发布的可执行文件；默认构建并运行当前工作树的 CLI。
if [ -n "${CRYPVOL_BIN:-}" ]; then
    CRYPVOL=("$CRYPVOL_BIN")
else
    echo "构建 Release CLI..."
    dotnet build "$ROOT_DIR/CrypVol.Cli/CrypVol.Cli.csproj" -c Release --nologo || exit 1
    CRYPVOL=(dotnet "$CLI_DLL")
fi

# ── helpers ──

check() {
    local name="$1"; shift
    local out rc
    out=$("$@" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name (rc=$rc)"
        [ -n "$out" ] && echo "    $(echo "$out" | head -3)"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

check_out() {
    local name="$1"; local pattern="$2"; shift 2
    local out rc
    out=$("$@" 2>&1)
    rc=$?
    if [ $rc -eq 0 ] && echo "$out" | grep -qE "$pattern"; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name (rc=$rc pattern=$pattern)"
        [ -n "$out" ] && echo "    $(echo "$out" | head -3)"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

check_fail() {
    local name="$1"; shift
    "$@" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name (应失败但成功)"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

skip() { echo -e "  ${YELLOW}⊘${NC} $1 (跳过)"; SKIP=$((SKIP+1)); }

run() { "${CRYPVOL[@]}" "$@" 2>&1; }
sha_all() { find "$1" -type f -exec sha256sum {} \; | sort -k2 | awk '{print $1}'; }

mk_files() {
    local d="$1"
    echo "hello" > "$d/hello.txt"
    mkdir -p "$d/nested/deep"
    echo "deeper" > "$d/nested/deep/file.txt"
    echo "nested" > "$d/nested/data.bin"
    dd if=/dev/urandom of="$d/random.bin" bs=1024 count=200 2>/dev/null
    echo "unicode" > "$d/测试文件.txt"
}

verify_extract() {
    local name="$1" src="$2" dst="$3" ref="$4"
    local extra="${5:-}"
    mkdir -p "$dst"
    if run extract "$src" $extra -o "$dst" >/dev/null 2>&1 && \
       diff <(sha_all "$ref") <(sha_all "$dst") >/dev/null 2>&1; then
        echo -e "  ${GREEN}✔${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✘${NC} $name"
        FAIL=$((FAIL+1)); FAILED+=("$name")
    fi
}

section() { echo -e "\n${CYAN}═══ $1 ═══${NC}"; }

# ═══════════════════════════════════════
section "1. genkey — 密钥生成"
# ═══════════════════════════════════════
check     "PlainKey"         run genkey -o "$TMP" -n k-plain
check     "Password"         run genkey -o "$TMP" -n k-pass -m Password -p "pwd123"
check     "含注释"            run genkey -o "$TMP" -n k-cmt -m Password -p "pwd" --comment "test"
check_fail "Asymmetric缺公钥" run genkey -o "$TMP" -n _asym -m Asymmetric
check_fail "Password缺密码"  run genkey -o "$TMP" -n _bad -m Password

# RSA keys
openssl genpkey -algorithm RSA -out "$TMP/priv.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl rsa -pubout -in "$TMP/priv.pem" -out "$TMP/pub.pem" 2>/dev/null
if [ -f "$TMP/pub.pem" ]; then
    check  "Asymmetric"       run genkey -o "$TMP" -n k-asym -m Asymmetric --public-key "$TMP/pub.pem"
    check  "多公钥"           run genkey -o "$TMP" -n k-asym2 -m Asymmetric \
        --public-key "$TMP/pub.pem" --public-key "$TMP/pub.pem"
else
    skip "Asymmetric (openssl不可用)"
fi

# ═══════════════════════════════════════
section "2. pack — 打包"
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

# Asymmetric pack
if [ -f "$TMP/k-asym.cvk" ]; then
    ASYM_DIR="$TMP/pack-Asymmetric"
    mkdir -p "$ASYM_DIR/input" "$ASYM_DIR/output"
    mk_files "$ASYM_DIR/input"
    check "pack Asymmetric" run pack "$ASYM_DIR/input" \
        -k "$TMP/k-asym.cvk" --privkey-key "$TMP/priv.pem" -o "$ASYM_DIR/output" --prefix Asym
    PACK_DIR[Asymmetric]="$ASYM_DIR"
fi

# 跨卷
SPLIT_DIR="$TMP/pack-split"
mkdir -p "$SPLIT_DIR/input" "$SPLIT_DIR/output"
dd if=/dev/urandom of="$SPLIT_DIR/input/big.bin" bs=1M count=15 2>/dev/null
check     "跨卷 15MB→5MB×4卷" run pack "$SPLIT_DIR/input" -m PlainKey -o "$SPLIT_DIR/output" --prefix split -s 5
cnt=$(find "$SPLIT_DIR/output" -name "split.*.cvp" | wc -l)
check     "跨卷验证卷数≥3"     [ "$cnt" -ge 3 ]

# --key-file 复用
mkdir -p "$TMP/pack-reuse/input" "$TMP/pack-reuse/output"
mk_files "$TMP/pack-reuse/input"
check     "--key-file 复用"     run pack "$TMP/pack-reuse/input" \
    -k "$TMP/k-pass.cvk" -p "pwd123" -o "$TMP/pack-reuse/output"

# 压缩
CMP_DIR="$TMP/pack-compress"
mkdir -p "$CMP_DIR/input" "$CMP_DIR/output"
mk_files "$CMP_DIR/input"
check     "默认压缩"             run pack "$CMP_DIR/input" -m PlainKey -o "$CMP_DIR/output"
check     "--compression-level SmallestSize" run pack "$CMP_DIR/input" -m PlainKey --compression-level SmallestSize -o "$TMP/pack-cmp9"
check     "--compression-level Fastest" run pack "$CMP_DIR/input" -m PlainKey --compression-level Fastest -o "$TMP/pack-cmp5"
check     "--integrity File" run pack "$CMP_DIR/input" -m PlainKey --integrity File -o "$TMP/pack-integrity-file"
check     "integrity File verify" run verify "$TMP/pack-integrity-file" -k "$TMP/pack-integrity-file/input.cvk"
check_fail "--chunk-size 0" run pack "$CMP_DIR/input" -m None --chunk-size 0 -o "$TMP/pack-invalid-chunk"
check_fail "--compression-level 非法预设" run pack "$CMP_DIR/input" -m PlainKey --compression-level 10 -o "$TMP/pack-invalid-compression"

# --include
mkdir -p "$TMP/pack-filter/input" "$TMP/pack-filter/output"
echo "a" > "$TMP/pack-filter/input/keep.txt"
echo "b" > "$TMP/pack-filter/input/skip.log"
check_out "pack --include" "卷"  run pack "$TMP/pack-filter/input" -m None -o "$TMP/pack-filter/output" --include "*.txt"

# --dry-run
check_out "pack --dry-run" "卷"  run pack "$TMP/pack-filter/input" -m None -o "$TMP/_dry" --dry-run

# --key-output 分离密钥目录
mkdir -p "$TMP/pack-ko/input" "$TMP/pack-ko/out" "$TMP/pack-ko/keys"
echo "x" > "$TMP/pack-ko/input/a.txt"
check     "--key-output"         run pack "$TMP/pack-ko/input" -m PlainKey -o "$TMP/pack-ko/out" --key-output "$TMP/pack-ko/keys"

# ═══════════════════════════════════════
section "3. extract — 还原验证"
# ═══════════════════════════════════════
for mode in None PlainKey Password; do
    d="${PACK_DIR[$mode]}"
    case $mode in
        None)     extra="" ;;
        PlainKey) extra="-k $d/output/${mode}.cvk" ;;
        Password) extra="-k $d/output/${mode}.cvk -p testpass" ;;
    esac
    verify_extract "extract $mode" "$d/output" "$TMP/ext-$mode" "$d/input" "$extra"
done

# Asymmetric extract
if [ -n "${PACK_DIR[Asymmetric]:-}" ]; then
    verify_extract "extract Asymmetric" "${PACK_DIR[Asymmetric]}/output" "$TMP/ext-asym" \
        "${PACK_DIR[Asymmetric]}/input" "-k $TMP/k-asym.cvk --privkey-key $TMP/priv.pem"
fi

verify_extract "extract 跨卷"      "$SPLIT_DIR/output"       "$TMP/ext-split"  "$SPLIT_DIR/input" \
    "-k $SPLIT_DIR/output/split.cvk"
verify_extract "extract 目录输入"   "${PACK_DIR[None]}/output" "$TMP/ext-dir"   "${PACK_DIR[None]}/input"

# --include / --exclude (run extract then check restored files)
D="${PACK_DIR[None]}/output"
run extract "$D" -o "$TMP/ext-inc" --include "*.txt" >/dev/null 2>&1
check     "extract --include"  [ -f "$TMP/ext-inc/hello.txt" ]
run extract "$D" -o "$TMP/ext-exc" --exclude "*.txt" >/dev/null 2>&1
check     "extract --exclude"  [ -f "$TMP/ext-exc/random.bin" ]

# --overwrite
mkdir -p "$TMP/ext-ow"
run extract "$D" -o "$TMP/ext-ow" >/dev/null 2>&1
check     "extract --overwrite"         run extract "$D" -o "$TMP/ext-ow" --overwrite

# 空文件
EMPTY_DIR="$TMP/empty"
mkdir -p "$EMPTY_DIR/input" "$EMPTY_DIR/output" "$EMPTY_DIR/restored"
touch "$EMPTY_DIR/input/empty.txt"
echo "x" > "$EMPTY_DIR/input/x.txt"
check     "pack 含空文件"              run pack "$EMPTY_DIR/input" -m PlainKey -o "$EMPTY_DIR/output"
verify_extract "extract 含空文件" "$EMPTY_DIR/output" "$EMPTY_DIR/restored" "$EMPTY_DIR/input" \
    "-k $EMPTY_DIR/output/input.cvk"


# 单字节文件
echo -n "X" > "$TMP/onebyte"
check     "pack 单文件"                run pack "$TMP/onebyte" -m None -o "$TMP/onebyte-out"

# unicode 文件名
UNI_DIR="$TMP/unicode"
mkdir -p "$UNI_DIR/input" "$UNI_DIR/output" "$UNI_DIR/restored"
echo "content" > "$UNI_DIR/input/文件名-测试.txt"
check     "pack unicode名"             run pack "$UNI_DIR/input" -m None -o "$UNI_DIR/output"
verify_extract "extract unicode名"     "$UNI_DIR/output" "$UNI_DIR/restored" "$UNI_DIR/input"

# ═══════════════════════════════════════
section "4. browse — 浏览"
# ═══════════════════════════════════════
B="${PACK_DIR[None]}/output"
check_out "browse 文件列表"   "hello"   run browse "$B"
check_out "browse -l 长格式"  "hello"   run browse "$B" -l
check_out "browse 跨卷"       "big"     run browse "$SPLIT_DIR/output" -l -k "$SPLIT_DIR/output/split.cvk"
check_out "browse --include"  "hello"   run browse "$B" --include "*.txt"
check     "browse --exclude"           run browse "$B" --exclude "nonexistent*"
check_fail "browse 不存在目录"           run browse "$TMP/_noexist"

# ═══════════════════════════════════════
section "5. verify / repair — 报告定位"
# ═══════════════════════════════════════
printf '\245' | dd of="$SPLIT_DIR/output/split.1.cvp" bs=1 seek=600 count=1 conv=notrunc status=none
REPORT="$TMP/reports/nested/damage.txt"
check_fail "verify 写入嵌套报告" run verify "$SPLIT_DIR/output/split.1.cvp" \
    -k "$SPLIT_DIR/output/split.cvk" --repair-report "$REPORT"
check      "损坏报告已创建"    test -s "$REPORT"
check      "repair 按卷定位"   run repair "$SPLIT_DIR/output/split.1.cvp" \
    -k "$SPLIT_DIR/output/split.cvk" --verify-report "$REPORT" -o "$TMP/repaired-report"
check      "报告修复输出"      test -f "$TMP/repaired-report/split.1.cvp"
check      "修复后 CRC 校验"   run verify "$TMP/repaired-report/split.1.cvp" \
    -k "$SPLIT_DIR/output/split.cvk"

# ═══════════════════════════════════════
section "6. info — 密钥信息"
# ═══════════════════════════════════════
check_out "info PlainKey"   "明文"     run info "$TMP/k-plain.cvk"
check_out "info Password"   "密码保护" run info "$TMP/k-pass.cvk" -p "pwd123"
check_out "info 编码模式"   "封装模式: 密码保护" run info "$TMP/k-pass.cvk" -p "pwd123"
check_out "info -p 正确密码" "CEK"     run info "$TMP/k-pass.cvk" -p "pwd123"
check_out "info 注释内容"   "注释: test" run info "$TMP/k-cmt.cvk" -p "pwd"
check_fail "info 非法文件"             run info "$TMP/not-a-key.txt"
check_fail "info 不存在文件"           run info "$TMP/_nokey.cvk"

if [ -f "$TMP/k-asym.cvk" ]; then
    check_out "info Asymmetric" "公钥保护" run info "$TMP/k-asym.cvk" --privkey-key "$TMP/priv.pem"
fi

# ═══════════════════════════════════════
section "7. rekey — 密钥重包装"
# ═══════════════════════════════════════
check     "Plain→Password"    run rekey "$TMP/k-plain.cvk" --to-mode Password --new-password "rp" -o "$TMP/k-rp.cvk"
check     "Password→Plain"    run rekey "$TMP/k-pass.cvk" -p "pwd123" --to-mode PlainKey -o "$TMP/k-back.cvk"
check     "Plain→Plain"       run rekey "$TMP/k-plain.cvk" --to-mode PlainKey -o "$TMP/k-rp2.cvk"
check_fail "Asymmetric缺公钥" run rekey "$TMP/k-plain.cvk" --to-mode Asymmetric

if [ -f "$TMP/pub.pem" ]; then
    check "Plain→Asymmetric"  run rekey "$TMP/k-plain.cvk" --to-mode Asymmetric --public-key "$TMP/pub.pem" -o "$TMP/k-ra.cvk"
    check "Asymmetric保留接收者" run rekey "$TMP/k-ra.cvk" --privkey-key "$TMP/priv.pem" \
        --to-mode Asymmetric -o "$TMP/k-ra-retained.cvk"
    check_out "保留接收者后可解封" "公钥保护" run info "$TMP/k-ra-retained.cvk" --privkey-key "$TMP/priv.pem"
fi

# rekey 后验证 extract: 对 pack 的密钥做 rekey 后用新密码提取
PK="${PACK_DIR[PlainKey]}/output/PlainKey.cvk"
check "rekey pack-key→Password" run rekey "$PK" --to-mode Password --new-password "rpx" -o "$TMP/k-rekeyed.cvk"
verify_extract "rekey后extract" "${PACK_DIR[PlainKey]}/output" "$TMP/ext-rekey" \
    "${PACK_DIR[PlainKey]}/input" "-k $TMP/k-rekeyed.cvk -p rpx"

# --backup
check     "rekey --backup"    run rekey "$TMP/k-rp2.cvk" --to-mode Password --new-password "bp" -b

# ═══════════════════════════════════════
section "8. convert — 块级密钥轮换"
# ═══════════════════════════════════════
CV_DIR="$TMP/convert"
mkdir -p "$CV_DIR/input" "$CV_DIR/output" "$CV_DIR/conv" "$CV_DIR/restored"
mk_files "$CV_DIR/input"
run pack "$CV_DIR/input" -m Password -p "cpwd" -o "$CV_DIR/output" --prefix cv >/dev/null

check     "convert pwd→plain"  run convert "$CV_DIR/output" \
    -k "$CV_DIR/output/cv.cvk" --old-password "cpwd" \
    --key-file "$TMP/k-plain.cvk" -o "$CV_DIR/conv"
check_fail "convert 缺目标CVK" run convert "$CV_DIR/output" \
    -k "$CV_DIR/output/cv.cvk" --old-password "cpwd" -o "$TMP/conv-without-key"
# After convert, the old cvk is still needed for the new volumes since we used --key-file (same CEK)
verify_extract "convert后extract" "$CV_DIR/conv" "$CV_DIR/restored" "$CV_DIR/input" \
    "-k $TMP/k-plain.cvk"

# pwd→pwd 密码轮换
CV2_DIR="$TMP/convert2"
mkdir -p "$CV2_DIR/out" "$CV2_DIR/conv" "$CV2_DIR/restored"
run pack "$CV_DIR/input" -m Password -p "oldp" -o "$CV2_DIR/out" --prefix cv2 >/dev/null
run genkey -o "$TMP" -n new-key -m Password -p "newp" >/dev/null
check     "convert pwd→pwd"    run convert "$CV2_DIR/out" \
    -k "$CV2_DIR/out/cv2.cvk" --old-password "oldp" \
    --key-file "$TMP/new-key.cvk" -p "newp" -o "$CV2_DIR/conv"
verify_extract "convert pwd→pwd后" "$CV2_DIR/conv" "$CV2_DIR/restored" "$CV_DIR/input" \
    "-k $TMP/new-key.cvk -p newp"

# --backup
check     "convert --backup"   run convert "$CV2_DIR/out" \
    -k "$CV2_DIR/out/cv2.cvk" --old-password "oldp" \
    --key-file "$TMP/k-plain.cvk" -o "$TMP/conv-bak" -b

# ═══════════════════════════════════════
section "9. 凭据校验"
# ═══════════════════════════════════════
PD="${PACK_DIR[Password]}/output"
check_fail "extract 缺密码"    run extract "$PD" -k "$PD/Password.cvk" -o "$TMP/_nopwd"
check_fail "extract 错密码"    run extract "$PD" -k "$PD/Password.cvk" -p "wrong" -o "$TMP/_wrong"
check       "extract 正确密码"  run extract "$PD" -k "$PD/Password.cvk" -p "testpass" -o "$TMP/_ok"

check_fail "info 错密码"       run info "$TMP/k-pass.cvk" -p "bad"
check_out  "info 正确密码" "CEK" run info "$TMP/k-pass.cvk" -p "pwd123"

check_fail "rekey 错旧密码"    run rekey "$TMP/k-pass.cvk" -p "bad" --to-mode PlainKey -o "$TMP/_"

# ═══════════════════════════════════════
section "10. 大文件 100MB"
# ═══════════════════════════════════════
BIG_DIR="$TMP/big"
mkdir -p "$BIG_DIR/input" "$BIG_DIR/output" "$BIG_DIR/restored"
dd if=/dev/zero of="$BIG_DIR/input/big.bin" bs=1M count=100 2>/dev/null
check     "100MB pack"         run pack "$BIG_DIR/input" -m PlainKey -o "$BIG_DIR/output" -s 40
verify_extract "100MB extract" "$BIG_DIR/output" "$BIG_DIR/restored" "$BIG_DIR/input" \
    "-k $BIG_DIR/output/input.cvk"

# ═══════════════════════════════════════
section "11. 边界场景"
# ═══════════════════════════════════════

# 空目录
mkdir -p "$TMP/emptydir/input" "$TMP/emptydir/output"
check_fail "pack 空目录"       run pack "$TMP/emptydir/input" -m None -o "$TMP/emptydir/output"

# 路径含空格
SPC_DIR="$TMP/path with spaces"
mkdir -p "$SPC_DIR/input" "$SPC_DIR/output" "$SPC_DIR/restored"
echo "spaces" > "$SPC_DIR/input/file name.txt"
check     "pack 空格路径"      run pack "$SPC_DIR/input" -m None -o "$SPC_DIR/output"
verify_extract "extract 空格"  "$SPC_DIR/output" "$SPC_DIR/restored" "$SPC_DIR/input"

# 直接输入 cvp 文件 browse
check_out "browse cvp文件" "file" run browse "$SPC_DIR/output"

# info 含注释密钥
check_out "info 注释"    "密码保护" run info "$TMP/k-cmt.cvk" -p "pwd"

# ═══════════════════════════════════════
section "结果"
# ═══════════════════════════════════════
echo -e "\n${CYAN}══════════════════════════════════════${NC}"
echo -e "${GREEN}通过: $PASS${NC}  ${RED}失败: $FAIL${NC}  ${YELLOW}跳过: $SKIP${NC}"
[ $FAIL -gt 0 ] && { echo -e "\n${RED}失败项:${NC}"; for f in "${FAILED[@]}"; do echo -e "  ${RED}✘${NC} $f"; done; }
exit $FAIL
