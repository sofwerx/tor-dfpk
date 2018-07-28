#!/bin/bash
curl -s http://cloud-images.ubuntu.com/locator/ec2/releasesTable | grep 'ebs-ssd' | grep bionic | sed -e 's/^\[//' -e 's/\],$//' -e 's/"//g' -e 's/,/  /g' -e 's/18.04 LTS/18.04/' -e 's/\<[^>]*\>//g' | awk '{print "	" $1 "-ubuntu-" $3 " = \"" $7 "\""}' | sort
