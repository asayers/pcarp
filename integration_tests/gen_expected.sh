#!/bin/bash -eu

# -a 'packets:100'
tshark -r $1 \
    -o frame.generate_md5_hash:TRUE \
    -tud \
    -Tfields -e _ws.col.Time -e frame.md5_hash |
    awk '{
        for (;length($2)<18;) $2=$2"0";
        printf("%sT%sZ\t%s\n", $1, $2, $3);
    }'
