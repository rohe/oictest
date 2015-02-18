#!/bin/bash

declare -A SERVICES

SERVICES=(["adfs"]="C.T.F.ns"
    ["azure_ad"]="C.T.F.ns"
    ["google"]="C.T.F.ns"
    ["ping"]="C.T.F.ns"
    ["salesforce"]="C.T.F.ns"
    ["telekom"]="C.T.F.ns"
    ["thinktecture_code"]="C.T.F.ns"
    ["thinktecture_impl"]="IT.T.F.ns"
    ["thinktecture_hybr"]="CIT.T.F.ns"
    ["luke"]="C.T.T.ns"
    ["edmund"]="C.T.T.ns"
    ["oictest_op"]="C.T.T.nse"
    ["gluu"]="C.T.T.nse")

startme() {
    for srv in "${!SERVICES[@]}" ; do
        NAME="${srv%%:*}"
        PROFILE="${SERVICES["$NAME"]}"
        ERRFILE="$NAME.err"

        ./oprp2.py -p ${PROFILE} -t tflow ${NAME} &> ${ERRFILE} &
    done
}

stopme() {
    for srv in "${SERVICES[@]}" ; do
        pkill -f "${srv%%:*}"
    done
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac