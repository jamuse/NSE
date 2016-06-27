#!/bin/bash

Path=$1
Output=$2
rm $Output
printf "<HTML><BODY><BR>" > $Output
ls -1 $Path/*.png | awk -F : '{ print $1":"$2"\n<BR><IMG SRC=\""$1"%3A"$2"\" width=400><BR><BR>"}' >> $Output
printf "</BODY></HTML>" >> $Output
