#!/bin/bash
. `dirname $0`/functions.sh
LIBS=`cat syslib.list`
comparelibs >> undosyslibs.log 2>&1 || exit 1
