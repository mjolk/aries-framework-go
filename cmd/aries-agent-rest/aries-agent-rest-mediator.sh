#!/usr/bin/zsh

../aries-agent-rest start --api-host localhost:8083 --inbound-host ws@localhost:8085 \
  --inbound-host-external ws@ws://7544-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io -l Router \
  --webhook-url http://localhost:8888/mediator --outbound-transport ws  --database-type leveldb \
  --log-level DEBUG \
   /


#http://70e0-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://0732-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://5fe8-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://3d93-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://ae46-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://e962-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://74e5-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
#http://7544-2a02-1810-391f-4b00-85ec-c8ed-7ecf-1dbd.ngrok.io
