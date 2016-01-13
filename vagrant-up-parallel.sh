#!/usr/bin/bash
# Very stupid bash script to run vagrant provisioning parallel

MAX_PROC=2

# this not so smart command will get all local vagrant machines (patches welcome)
MACHINES=$(vagrant status | head -n -4 | tail -n +3 | cut -f 1 -d ' ')
if [ $? -ne 0 ]; then
    echo "Something bad happened, could not get list of vagrant machines"
    echo "END."
    exit
fi

# run only provisioning in parallel, otherwise it will release the krakken
vagrant up --no-provision

# run provisioning
# xargs might be better (patches welcome)
for machine in ${MACHINES[@]}; do
    vagrant provision $machine &  # do magic
    proc=$(($proc+1))
    if [ "$proc" -ge $MAX_PROC ]; then
        wait  # until a part of magic is done
        proc=0
    fi
done
