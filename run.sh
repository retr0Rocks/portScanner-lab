#!/usr/bin/bash

# This is the main script wheremain execution should start
# this bash script executes all the necessary command: doing port scan, parsing json output then passing it to ElasticSearch.
# To execute this binary we pass it few arguemnts such as the host file and the port range to scan.
# example : ./ape.sh -f hosts.txt -r 1-500

while getopts ":f:r:" flag; do
    case "${flag}" in
        f) file_path=${OPTARG} ;;
        r) range=${OPTARG} ;;
    esac
done

if [ ! -f "$file_path" ]; then
    echo "File not found: $file_path"
    exit 1
fi

rm out.json
smap -p$range -iL $file_path -oJ out.json -T 2
#sed -i 's/]\[/,/g' out.json
python3 magic.py out.json 500
python3 ela.py
