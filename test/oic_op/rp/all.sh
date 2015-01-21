#!/bin/bash

startme() {
    ./oprp2.py -p C.T.F -t tflow adfs &> adfs.err &
    ./oprp2.py -p I.T.F -t tflow adfs_i &> adfs_i.err &
    ./oprp2.py -p IT.T.F -t tflow adfs_it &> adfs_it.err &

    ./oprp2.py -p C.T.F -t tflow azure_ad &> azure.err &
    ./oprp2.py -p I.T.F -t tflow azure_ad_i &> azure_i.err &
    ./oprp2.py -p IT.T.F -t tflow azure_ad_it &> azure_it.err &

    ./oprp2.py -p C.T.F -t tflow google &> google.err &
    ./oprp2.py -p C.T.F -t tflow ping &> ping.err &
    ./oprp2.py -p C.T.F -t tflow salesforce &> salesforce.err &
    ./oprp2.py -p C.T.F -t tflow telekom &> telekom.err &
    ./oprp2.py -p C.T.F -t tflow thinktecture_code &> thinktecture_code.err &

    ./oprp2.py -p C.T.T -t tflow luke &> luke.err &
    ./oprp2.py -p C.T.T -t tflow edmund &> edmund.err &
    ./oprp2.py -p C.T.T -t tflow xenosmilus2 &> xenosmilus2.err &
}

stopme() {
    pkill -f "adfs"
    pkill -f "azure_ad"
    pkill -f "google"
    pkill -f "ping"
    pkill -f "salesforce"
    pkill -f "telekom"
    pkill -f "thinktecture_code"
    pkill -f "luke"
    pkill -f "edmund"
    pkill -f "xenosmilus2"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac