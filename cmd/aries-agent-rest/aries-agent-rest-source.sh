#!/usr/bin/zsh

../aries-agent-rest start --api-host localhost:8080 --inbound-host ws@localhost:8082 --inbound-host-external ws@ws://localhost:8082 \
   --webhook-url http://localhost:8888/agent -l Agent --outbound-transport ws --transport-return-route all --database-type leveldb \
   --log-level DEBUG \
   /
