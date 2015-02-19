#!/bin/bash

declare -A SERVICES

SERVICES=(["asfar"]="C.F.F.ns")

startme() {
    for srv in "${!SERVICES[@]}" ; do
        NAME="${srv%%:*}"
        PROFILE="${SERVICES["$NAME"]}"
        ERRFILE="$NAME.err"

        ./oprp_gsma.py -p ${PROFILE} -t tests ${NAME} &> ${ERRFILE} &
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