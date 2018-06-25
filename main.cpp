#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <cstring>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

//helper functions
int create_socket(int port)
{
	int s;

	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);

	if (s < 0) {
		perror("Unable to create socket");

		exit(EXIT_FAILURE);
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");

		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");

		exit(EXIT_FAILURE);
	}
	return s;
}

void init_openssl()
{
	SSL_load_error_strings();

	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;

	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);

	if (!ctx) {
		perror("Unable to create SSL context");

		ERR_print_errors_fp(stderr);

		exit(EXIT_FAILURE);
	}

	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);

		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);

		exit(EXIT_FAILURE);
	}
}

// RAII Handles
struct OpenSSL {
	OpenSSL()  { init_openssl(); }
	~OpenSSL() { cleanup_openssl(); }
};

struct Socket {
	Socket(int Port) : _socket{create_socket(Port)} { }
	~Socket() { close(_socket); }

	auto operator()() -> int { return _socket; }

	private:
	int _socket;

};

struct SSLContext {
	SSLContext() : _ctx{create_context()} { configure_context(_ctx); }
	~SSLContext() { SSL_CTX_free(_ctx); }

	auto operator()() -> SSL_CTX* { return _ctx; }

	private:
	SSL_CTX * _ctx;
};

struct Client {
	Client(Socket sock, sockaddr_in addr, socklen_t len)
		: _client{accept(sock(), (struct sockaddr*) &addr, &len)} {
			if (_client < 0) {
				perror("Unable to accept");

				exit(EXIT_FAILURE);
			}
		}
	~Client() { close(_client); }

	auto operator()() -> int { return _client; }

	private:
	int _client;
};

struct SSLHandle {
	SSLHandle(SSLContext & ctx) : _ssl{SSL_new( ctx() ) } { }
	~SSLHandle() { SSL_free(_ssl); }

	auto operator()() -> SSL * { return _ssl; }
	private:
	SSL * _ssl;
};

int main(int argc, char **argv)
{
	const auto sessionHandle = OpenSSL {};
	const auto PORT = atoi( getenv("TLS_SERV_PORT") );
	const auto sock = Socket { PORT };

	auto ctx = SSLContext {};

	std::cout << "Listening on port " << PORT << '\n';

	while(1) { /* Handle connections */
		struct sockaddr_in addr;

		auto ssl = SSLHandle{ ctx };
		auto client = Client{ sock, addr, sizeof(addr) };

		SSL_set_fd(ssl(), client());

		if (SSL_accept(ssl()) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			const char reply[] = "test\n";

			SSL_write(ssl(), reply, strlen(reply));
		}
	}
}
