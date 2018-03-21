#!/bin/bash
echo "Filename "
read fn
echo "Listen for (in Seconds)"
read sec
tcpdump -i any -w $fn".pcap"&
pid=$!
sleep $sec
kill $pid
echo "Completed"
