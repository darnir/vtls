/*
 * Copyright(c) 2015 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libvtls.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <vtls.h>
#include <netdb.h>

#ifndef SOCK_NONBLOCK
static void _set_async(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		fprintf(stderr, "Failed to get socket flags\n");

	if (fcntl(fd, F_SETFL, flags | O_NDELAY) < 0)
		fprintf(stderr, "Failed to set socket to non-blocking\n");
}
#endif

static int _get_async_socket(void)
{
	int sockfd;

#ifdef SOCK_NONBLOCK
	if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) != -1) {
		int on = 1;
#else
	if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) != -1) {
		int on = 1;

		_set_async(sockfd);
#endif
/*
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
			fprintf(stderr, "Failed to set socket option REUSEADDR\n");

		on = 1;
		if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
			fprintf(stderr, "Failed to set socket option NODELAY\n");
*/
	}

	return sockfd;
}

int _get_connected_socket(const char *host, int port)
{
	struct addrinfo *addrinfo, hints;
	int rc, sockfd;

	if ((sockfd = _get_async_socket()) == -1) {
		fprintf(stderr, "Failed to get socket\n");
		return -1;
	}

	memset(&hints, 0 ,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
}

int main(int argc, const char *const *argv)
{
	vtls_session_t *sess = NULL;
	vtls_config_t *default_config;
	struct addrinfo *addrinfo, hints;
	int rc, sockfd;
	ssize_t nbytes;
	char buf[2048];

	if ((rc = getaddrinfo("www.google.com", 443, &hints, &addrinfo))) {
		fprintf(stderr, "Failed to resolve (%s)\n", gai_strerror(rc));
		return 1;
	}

	if ((rc = connect(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen))) {
		fprintf(stderr, "Failed to connect (%s)\n", rc);
		return 1;
	}

	/*
	 * Plain text connection has been established.
	 * Before we establish the TLS layer, we could send/recv plain text here.
	 */

	/* optional example of how to set default config values */
	if (vtls_config_init(&default_config,
		VTLS_CFG_TLS_VERSION, CURL_SSLVERSION_TLSv1_0,
		VTLS_CFG_VERIFY_PEER, 1,
		VTLS_CFG_VERIFY_HOST, 1,
		VTLS_CFG_VERIFY_STATUS, 1,
		VTLS_CFG_CA_PATH, "/etc/ssl/certs",
		VTLS_CFG_CA_FILE, NULL,
		VTLS_CFG_CRL_FILE, NULL,
		VTLS_CFG_ISSUER_FILE, NULL,
		VTLS_CFG_RANDOM_FILE, NULL,
		VTLS_CFG_EGD_SOCKET, NULL,
		VTLS_CFG_CIPHER_LIST, NULL,
		VTLS_CFG_LOCK_CALLBACK, NULL,
		NULL))
	{
		fprintf(stderr, "Failed to init default config\n");
		return 1;
	}

	/* call vtls_init(NULL) to use library defaults */
	if (vtls_init(default_config)) {
		fprintf(stderr, "Failed to init vtls\n");
		return 1;
	}

	if ((rc = vtls_session_init(&sess, NULL, sockfd))) {
		fprintf(stderr, "Failed to init vtls session init (%d)\n", rc);
		return 1;
	}

	if ((rc = vtls_connect(sess))) {
		fprintf(stderr, "Failed to connect (%d)\n", rc);
		return 1;
	}

	if ((nbytes = vtls_write(sess, HTTP_REQUEST, sizeof(HTTP_REQUEST) - 1)) < 0) {
		fprintf(stderr, "Failed to write (%d)\n", rc);
		return 1;
	}

	while ((nbytes = vtls_read(sess, buf, sizeof(buf))) >= 0) {
		fwrite(buf, 1, nbytes, stdout)
	}

	if ((rc = vtls_close(sess))) {
		fprintf(stderr, "Failed to init vtls session init\n");
		return 1;
	}

	vtls_session_deinit(&sess);
	vtls_deinit();

	/*
	 * TLS connection has been shut down, but the connection is still valid.
	 * We could again send/recv plain text here.
	 */

	freeaddrinfo(addrinfo);
	close(sockfd);
}
