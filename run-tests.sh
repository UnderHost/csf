#!/bin/sh
###############################################################################
# CSF 2.0 - run the Perl test suite. Usage: ./run-tests.sh
###############################################################################
cd "$(dirname "$0")" || exit 1

total=0
fail=0
for t in t/*.t; do
    out=$(perl "$t" 2>&1)
    rc=$?
    n=$(printf '%s\n' "$out" | grep -c '^ok')
    total=$((total + n))
    if [ $rc -eq 0 ] && ! printf '%s\n' "$out" | grep -q 'not ok'; then
        printf '  %-18s PASS (%s)\n' "$(basename "$t")" "$n"
    else
        printf '  %-18s FAIL\n' "$(basename "$t")"
        printf '%s\n' "$out" | grep -E 'not ok|error|aborted|Global symbol' | head -5
        fail=$((fail + 1))
    fi
done
echo "-------------------------------------------"
echo "TOTAL: $total assertions, $fail failing file(s)"
[ $fail -eq 0 ] || exit 1
