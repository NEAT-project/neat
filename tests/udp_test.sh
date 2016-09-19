#!/bin/sh

peer=../peer

IP=127.0.0.1
PORT=6969
FILE=test.txt
RATE=90

STAGEDIR=stage

clientcmd= $peer -h $IP -p $PORT -f $FILE -D $RATE
servercmd= $peer -p $PORT -D $RATE

sendfile=test.txt
recvfile=$STAGEDIR/$sendfile

if [ ! -d "$dirname" ]
then
	mkdir $STAGEDIR
fi

cd $STAGEDIR

$(servercmd) &
server = $!

cd ..
ret=$(clientcmd)
pkill $server

if [ "$ret" == 0 ]
then
	return 1
else
	srcsum=`shasum $sendfile | awk '{ print \$1}'`
	dstsum=`shasum $recvfile | awk '{ print \$1}'`

	if [ "$srcsum" == "$dstsum" ] 
	then 
		exit 0
	if
	exit 1
fi
