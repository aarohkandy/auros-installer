#!/bin/sh
# Inside the pinned Go container: add the three tools prove-red.sh needs, then run it.
apk add --no-cache bash python3 tar >/dev/null 2>&1 || { echo "apk failed"; exit 1; }
cd /src && bash tools/prove-red.sh "$@"
