#!/bin/sh

echo "Starting server..."
hydra serve -c /opt/hydra.yml all --dangerous-force-http &

echo "Waiting for server to start..."
sleep 20

echo "Creating clients..."
hydra clients create --endpoint http://localhost:4445/ --id 30ad6340-8706-47d1-baef-868208334609 --secret phae-Vei5phi1xu8 --grant-types client_credentials --scope "entity_creation,signature_endpoint,update_credential"
hydra clients create --endpoint http://localhost:4445/ --id c85a016e-9c4a-4978-b110-d12902217992 --secret riezahd-o4IZue8u --grant-types client_credentials --scope "entity_creation,signature_endpoint,update_credential"
hydra clients create --endpoint http://localhost:4445/ --id dbf2c28a-bfc0-4a89-b304-0319b48ff438 --secret ohM-ei1ieheimeiz --grant-types client_credentials --scope "entity_creation,signature_endpoint,update_credential"

echo "Startup done..."
sleep infinity
