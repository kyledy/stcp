#!/bin/bash
file=smallfile
rm -f OutputFile
pkill sender
pkill receiver
./waitForPorts
./receiver & sleep 1
./sender   $file
sleep 2
pkill receiver
diff $file OutputFile
