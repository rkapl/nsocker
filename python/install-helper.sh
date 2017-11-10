#!/bin/sh
# This helper is needed to make the destdir absolute
if [ -z "$DESTDIR" ]; then
    DESTDIR=/
fi
cd "$DESTDIR"
export DESTDIR="`pwd`"
cd "$1"
shift
"$@" --root="$DESTDIR"
