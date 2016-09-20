#!/bin/sh

peer=../examples/peer

IP=127.0.0.1
PORT=6969
FILE=test.txt
RATE=90
LOGLEVEL=0

STAGEDIR=stage

export NEAT_LOG_LEVEL=NEAT_LOG_OFF

clientcmd="$peer -h $IP -p $PORT -f $FILE -D $RATE -v $LOGLEVEL"
servercmd="$peer -p $PORT -D $RATE -v $LOGLEVEL"

sendfile="test.txt"
recvfile=$STAGEDIR/$sendfile

if [ ! -d "$dirname" ]
then
	mkdir $STAGEDIR
fi

cd $STAGEDIR

eval ../$servercmd &
server=$!

echo "SERVER PID $server"

cd ..
ret=eval $clientcmd
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
	fi
	exit 1
fi
