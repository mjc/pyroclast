#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
oracle="$repo/scripts/oracle/xctrace-cpu.xsl"
[ -f "$oracle" ] || { echo 'missing independent xctrace XML oracle' >&2; exit 1; }
command -v xsltproc >/dev/null || { echo 'xsltproc is required for oracle tests' >&2; exit 1; }
mkdir -p "$repo/target"
root=$(mktemp -d "$repo/target/xctrace-oracle.XXXXXX")
trap 'rm -rf "$root"' EXIT
extract() {
    xsltproc --nonet --stringparam target-pid "$2" "$oracle" "$1" | jq -s .
}
extract "$repo/tests/fixtures/xctrace/cpu-profile-xcode27.xml" 7 > "$root/native.json"
jq -e 'length == 4 and (map(.weight) | add) == 2024198 and
    all(.weight_unit == "cycles") and .[2].symbol == "hot_loop" and
    .[3].symbol == "hot_loop"' "$root/native.json" >/dev/null
extract "$repo/tests/fixtures/xctrace/cpu-profile-xcode27.xml" 8 | jq -e 'length == 0' >/dev/null
cat > "$root/refs.xml" <<'XML'
<trace-query-result><node><schema name="time-profile"/>
<row><thread id="t"><process id="p"><pid id="pid">7</pid></process></thread><weight id="w">12.5</weight><backtrace id="b"><frame id="f" name="a&amp;b&lt;T&gt;&quot;\&#9;&#10;"/><frame name="root"/></backtrace></row>
<row><thread ref="t"/><weight ref="w"/><tagged-backtrace><backtrace ref="b"/></tagged-backtrace></row>
<row><thread ref="t"/><weight>19579</weight><sentinel/></row>
<row><process pid="8"/><weight>99</weight><symbol>other</symbol></row>
<row><process><pid ref="pid"/></process><weight>2</weight><backtrace><frame ref="f"/></backtrace></row>
</node></trace-query-result>
XML
extract "$root/refs.xml" 7 > "$root/refs.json"
jq -e 'length == 3 and (map(.weight) | add) == 27 and
    all(.weight_unit == "nanoseconds") and
    all(.symbol == "a&b<T>\"\\")' "$root/refs.json" >/dev/null
for cells in \
    '<process pid="7"/><weight>1</weight><backtrace ref="missing"/>' \
    '<process pid="7"/><weight>1</weight><backtrace id="b" ref="b"/>' \
    '<process pid="7"/><weight>1</weight><backtrace/>' \
    '<process pid="7"/><weight>1</weight><sentinel/><backtrace ref="missing"/>' \
    '<process pid="7"/><weight>NaN</weight><symbol>bad</symbol>' \
    '<process pid="7"/><weight>-1</weight><symbol>bad</symbol>' \
    '<process pid="7"/><weight>1</weight><cycle-weight>2</cycle-weight><symbol>bad</symbol>'; do
    printf '<trace-query-result><node><schema name="time-profile"/><row>%s</row></node></trace-query-result>\n' "$cells" > "$root/bad.xml"
    if extract "$root/bad.xml" 7 > "$root/bad.json" 2> "$root/error"; then
        echo "oracle accepted invalid cells: $cells" >&2
        exit 1
    fi
done
printf '<broken>' > "$root/bad.xml"
if extract "$root/bad.xml" 7 > "$root/bad.json" 2> "$root/error"; then
    echo 'oracle accepted malformed XML' >&2
    exit 1
fi
echo 'independent xctrace XML oracle checks passed'
