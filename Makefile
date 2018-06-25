CERT=cert.pem

.PHONY: check run build

run: build $(CERT)
	pkill main || true && ./main &

build:
	g++ --std=c++11 main.cpp -lssl -lcrypto -o main

$(CERT):
	openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out $@ -subj "/C=US/ST=New York/L=Brooklyn/O=Example Brooklyn Company/CN=examplebrooklyn.com"

check: run
	openssl s_client -connect localhost:$(TLS_SERV_PORT)
