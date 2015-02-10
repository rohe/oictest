#!/bin/bash

startme() {
    ./oprp2.py -p C.T.F.ns -t tflow adfs &> adfs.err &
    ./oprp2.py -p C.T.F.ns -t tflow azure_ad &> azure.err &

    ./oprp2.py -p C.T.F.ns -t tflow google &> google.err &
    ./oprp2.py -p C.T.F.ns -t tflow ping &> ping.err &
    ./oprp2.py -p C.T.F.ns -t tflow salesforce &> salesforce.err &
    ./oprp2.py -p C.T.F.ns -t tflow telekom &> telekom.err &

    ./oprp2.py -p C.T.F.ns -t tflow thinktecture_code &> thinktecture_code.err &
    ./oprp2.py -p IT.T.F.ns -t tflow thinktecture_impl &> thinktecture_impl.err &
    ./oprp2.py -p CIT.T.F.ns -t tflow thinktecture_hybr &> thinktecture_hybr.err &

    ./oprp2.py -p C.T.T.ns -t tflow luke &> luke.err &
    ./oprp2.py -p C.T.T.ns -t tflow edmund &> edmund.err &
    ./oprp2.py -p C.T.T.nse -t tflow oictest_op &> oictest.err &
    ./oprp2.py -p C.F.F -t tflow gsma &> gsma.err &
}

stopme() {
    pkill -f "adfs"
    pkill -f "azure_ad"
    pkill -f "google"
    pkill -f "ping"
    pkill -f "salesforce"
    pkill -f "telekom"
    pkill -f "thinktecture"
    pkill -f "luke"
    pkill -f "edmund"
    pkill -f "xenosmilus2"
    pkill -f "oictest_op"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac