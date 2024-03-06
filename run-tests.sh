#!/bin/bash

repeat(){
    local range=$(seq 1 $1)
    for i in $range ; do echo -n "$2"; done
}

IFS=$'\n' read -r -d '' -a MODULE_ARRAY < <( find ./ -type f -name "go.mod" )

set -e

for value in "${MODULE_ARRAY[@]}"
do
    if [ -f "$value" ]; then
        DIR_NAME="$(dirname "$value")"
        TESTS_FOUND="$(find "$DIR_NAME" -type f -name "*_test.go")"
        if [ "$TESTS_FOUND" != "0" ]; then
            echo "---------- $value ----------"
            go test -C "$DIR_NAME"
            echo -n "-----------"
            repeat "${#value}" "-"
            echo "-----------"
            echo ""
        fi
    fi
done