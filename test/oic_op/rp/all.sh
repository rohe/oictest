#!/bin/bash

startme() {
    ./oprp2.py -p BTF -t tflow adfs &> adfs.err &
    ./oprp2.py -p BTF -t tflow azure_ad &> azure.err &
    ./oprp2.py -p BTF -t tflow google &> google.err &
    ./oprp2.py -p BTF -t tflow ping &> ping.err &
    ./oprp2.py -p BTF -t tflow salesforce &> salesforce.err &
    ./oprp2.py -p BTF -t tflow telekom &> telekom.err &
    ./oprp2.py -p BTF -t tflow thinktecture_code &> thinktecture_code.err &
    ./oprp2.py -p ITF -t tflow adfs_implicit &> adfs_implicit.err &
    ./oprp2.py -p ITF -t tflow azure_ad_implicit &> azure_implicit.err &
}

stopme() {
    pkill -f "adfs"
    pkill -f "azure_ad"
    pkill -f "google"
    pkill -f "ping"
    pkill -f "salesforce"
    pkill -f "telekom"
    pkill -f "thinktecture_code"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac