/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* This file is for implementing all "generic" SSL functions that all libcurl
	internals should use. It is then responsible for calling the proper
	"backend" function.

	SSL-functions in libcurl should call functions in this source file, and not
	to any specific SSL-layer.

	vtls_ - prefix for generic ones
	Curl_ossl_ - prefix for OpenSSL ones
	Curl_gtls_ - prefix for GnuTLS ones
	Curl_nss_ - prefix for NSS ones
	Curl_gskit_ - prefix for GSKit ones
	Curl_polarssl_ - prefix for PolarSSL ones
	Curl_cyassl_ - prefix for CyaSSL ones
	Curl_schannel_ - prefix for Schannel SSPI ones
	Curl_darwinssl_ - prefix for SecureTransport (Darwin) ones

	Note that this source code uses curlssl_* functions, and they are all
	defines/macros #defined by the lib-specific header files.

	"SSL/TLS Strong Encryption: An Introduction"
	http://httpd.apache.org/docs-2.0/ssl/ssl_intro.html
 */

// #include "curl_setup.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// #include "urldata.h"

#include <vtls.h> /* generic SSL protos etc */
#include "timeval.h"

/*
#include "slist.h"
#include "sendf.h"
#include "rawstr.h"
#include "url.h"
#include "curl_memory.h"
#include "progress.h"
#include "share.h"
#include "timeval.h"
#include "curl_md5.h"
#include "warnless.h"
#include "curl_base64.h"
 */

#define _MPRINTF_REPLACE /* use our functions only */
// #include <curl/mprintf.h>

/* The last #include file should be: */
// #include "memdebug.h"

/* convenience macro to check if this handle is using a shared SSL session */
#define SSLSESSION_SHARED(data) (data->share &&                        \
                                 (data->share->specifier &             \
                                  (1<<CURL_LOCK_DATA_SSL_SESSION)))

#define xfree(a) do { if (a) { free((void *)(a)); a = NULL; } } while (0)

static const char _lower[256] = {
	['a'] = 'a', ['b'] = 'b', ['c'] = 'c', ['d'] = 'd',
	['e'] = 'e', ['f'] = 'f', ['g'] = 'g', ['h'] = 'h',
	['i'] = 'i', ['j'] = 'j', ['k'] = 'k', ['l'] = 'l',
	['m'] = 'm', ['n'] = 'n', ['o'] = 'o', ['p'] = 'p',
	['q'] = 'q', ['r'] = 'r', ['s'] = 's', ['t'] = 't',
	['u'] = 'u', ['v'] = 'v', ['w'] = 'w', ['x'] = 'x',
	['y'] = 'y', ['z'] = 'z', ['A'] = 'a', ['B'] = 'b',
	['C'] = 'c', ['D'] = 'd', ['E'] = 'e', ['F'] = 'f',
	['G'] = 'g', ['H'] = 'h', ['I'] = 'i', ['J'] = 'j',
	['K'] = 'k', ['L'] = 'l', ['M'] = 'm', ['N'] = 'n',
	['O'] = 'o', ['P'] = 'p', ['Q'] = 'q', ['R'] = 'r',
	['S'] = 's', ['T'] = 't', ['U'] = 'u', ['V'] = 'v',
	['W'] = 'w', ['X'] = 'x', ['Y'] = 'y', ['Z'] = 'z',
};

/**
 * vtls_strcasecmp_ascii:
 * @s1: String
 * @s2: String
 *
 * This functions compares @s1 and @s2 case insensitive ignoring locale settings.
 * It also accepts %NULL values.
 *
 * It returns 0 if both @s1 and @s2 are the same disregarding case for ASCII letters a-z.
 * It returns 0 if both @s1 and @s2 are %NULL.
 * It returns <0 if @s1 is %NULL and @s2 is not %NULL or s1 is smaller than s2.
 * It returns >0 if @s2 is %NULL and @s1 is not %NULL or s1 is greater than s2.
 *
 * Returns: An integer value described above.
 */
int vtls_strcasecmp_ascii(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else {
			while (*s1 && (*s1 == *s2 || (_lower[(unsigned)*s1] && _lower[(unsigned)*s1] == _lower[(unsigned)*s2]))) {
				s1++;
				s2++;
			}

			if (*s1 || *s2)
				return *s1 - *s2;

			return 0;
		}
	}
}

/**
 * vtls_strncasecmp_ascii:
 * @s1: String
 * @s2: String
 * @n: Max. number of chars to compare
 *
 * This functions compares @s1 and @s2 case insensitive ignoring locale settings up to a max number of @n chars.
 * It also accepts %NULL values.
 *
 * It returns 0 if both @s1 and @s2 are the same disregarding case for ASCII letters a-z.
 * It returns 0 if both @s1 and @s2 are %NULL.
 * It returns <0 if @s1 is %NULL and @s2 is not %NULL or s1 is smaller than s2.
 * It returns >0 if @s2 is %NULL and @s1 is not %NULL or s1 is greater than s2.
 *
 * Returns: An integer value described above.
 */
int vtls_strncasecmp_ascii(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else {
			while ((ssize_t)(n--) > 0 && *s1 && (*s1 == *s2 || (_lower[(unsigned)*s1] && _lower[(unsigned)*s1] == _lower[(unsigned)*s2]))) {
				s1++;
				s2++;
			}

			if ((ssize_t)n >= 0 && (*s1 || *s2))
				return *s1 - *s2;

			return 0;
		}
	}
}

static int safe_strequal(const char* str1, const char* str2)
{
	return vtls_strncasecmp_ascii(str1, str2) == 0;
}

int vtls_config_matches(const ssl_config_data_t data, const ssl_config_data_t needle)
{
	return
	((data->version == needle->version) &&
		(data->verifypeer == needle->verifypeer) &&
		(data->verifyhost == needle->verifyhost) &&
		safe_strequal(data->CApath, needle->CApath) &&
		safe_strequal(data->CAfile, needle->CAfile) &&
		safe_strequal(data->random_file, needle->random_file) &&
		safe_strequal(data->egdsocket, needle->egdsocket) &&
		safe_strequal(data->cipher_list, needle->cipher_list));
}

int vtls_config_clone(
	struct ssl_config_data *source,
	struct ssl_config_data *dest)
{
	dest->sessionid = source->sessionid;
	dest->verifyhost = source->verifyhost;
	dest->verifypeer = source->verifypeer;
	dest->version = source->version;

	if (source->CAfile) {
		dest->CAfile = strdup(source->CAfile);
		if (!dest->CAfile)
			return 0;
	} else
		dest->CAfile = NULL;

	if (source->CApath) {
		dest->CApath = strdup(source->CApath);
		if (!dest->CApath)
			return 0;
	} else
		dest->CApath = NULL;

	if (source->cipher_list) {
		dest->cipher_list = strdup(source->cipher_list);
		if (!dest->cipher_list)
			return 0;
	} else
		dest->cipher_list = NULL;

	if (source->egdsocket) {
		dest->egdsocket = strdup(source->egdsocket);
		if (!dest->egdsocket)
			return 0;
	} else
		dest->egdsocket = NULL;

	if (source->random_file) {
		dest->random_file = strdup(source->random_file);
		if (!dest->random_file)
			return 0;
	} else
		dest->random_file = NULL;

	return 1;
}

void vtls_config_free(struct ssl_config_data* sslc)
{
	xfree(sslc->CAfile);
	xfree(sslc->CApath);
	xfree(sslc->cipher_list);
	xfree(sslc->egdsocket);
	xfree(sslc->random_file);
}

/*
 * Curl_rand() returns a random unsigned integer, 32bit.
 *
 * This non-SSL function is put here only because this file is the only one
 * with knowledge of what the underlying SSL libraries provide in terms of
 * randomizers.
 *
 * NOTE: 'data' may be passed in as NULL when coming from external API without
 * easy handle!
 *
 */

unsigned int vtls_rand(struct SessionHandle *data, int force_entropy, const char *random_file)
{
	unsigned int r = 0;
	static unsigned int randseed;
	static int seeded = 0;

	if (force_entropy) {
		if (!seeded) {
			size_t elen = strlen(force_entropy);
			size_t clen = sizeof(randseed);
			size_t min = elen < clen ? elen : clen;
			memcpy((char *) &randseed, force_entropy, min);
			seeded = 1;
		} else
			randseed++;

		return randseed;
	}

	/* data may be NULL! */
	if (!backend_random(data, (unsigned char *) &r, sizeof(r)))
		return r;

	/* If vtls_random() returns non-zero it couldn't offer randomness and we
		instead perform a "best effort" */

	if (random_file) {
		if (!seeded) {
			/* if there's a random file to read a seed from, use it */
			int fd = open(random_file, O_RDONLY);
			if (fd > -1) {
				/* read random data into the randseed variable */
				ssize_t nread = read(fd, &randseed, sizeof(randseed));
				if (nread == sizeof(randseed))
					seeded = 1;
				close(fd);
			}
		}
	}

	if (!seeded) {
		struct timeval now = curlx_tvnow();
		printf("WARNING: Using weak random seed\n");
		randseed += (unsigned int) now.tv_usec + (unsigned int) now.tv_sec;
		randseed = randseed * 1103515245 + 12345;
		randseed = randseed * 1103515245 + 12345;
		randseed = randseed * 1103515245 + 12345;
		seeded = 1;
	}

	/* Return an unsigned 32-bit pseudo-random number. */
	r = randseed = randseed * 1103515245 + 12345;
	return(r << 16) | ((r >> 16) & 0xFFFF);
}

int vtls_get_engine(void)
{
	return backend_get_engine();
}

/* "global" init done? */
static int _init_vtls = 0;

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int vtls_init(void)
{
	/* make sure this is only done once */
	if (_init_vtls++)
		return 1;

	return backend_init();
}

/* Global cleanup */
void vtls_deinit(void)
{
	if (--_init_vtls == 0) {
		/* only cleanup if we did a previous init */
		backend_deinit();
	}
}

int vtls_connect(struct vtls_session_t *sess, int sockfd)
{
	int result;

	/* mark this is being ssl-enabled from here on. */
	sess->sockfd = sockfd;
	sess->use = 1;
	sess->state = ssl_connection_negotiating;

	result = backend_connect(sess);

//	if (!result)
//		Curl_pgrsTime(conn->data, TIMER_APPCONNECT); /* SSL is connected */

	return result;
}

int vtls_connect_nonblocking(vtls_session_t *sess, int *done)
{
	int result;
	/* mark this is being ssl requested from here on. */
	sess.use = 1;
#ifdef curlssl_connect_nonblocking
	result = curlssl_connect_nonblocking(conn, sockindex, done);
#else
	*done = 1; /* fallback to BLOCKING */
	result = backend_connect(sess);
#endif /* non-blocking connect support */

	return result;
}

void vtls_close(vtls_session_t *sess)
{
//	DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));
	backend_close(sess);
}

int vtls_shutdown(vtls_session_t *sess)
{
	if (backend_shutdown(sess))
		return CURLE_SSL_SHUTDOWN_FAILED;

	sess->use = 0;
	sess->state = ssl_connection_none;

	return 0;
}

size_t vtls_version(char *buffer, size_t size)
{
	return backend_version(buffer, size);
}

void vtls_free_certinfo(struct SessionHandle *data)
{
	int i;
//	struct curl_certinfo *ci = &data->info.certs;
	struct curl_certinfo *ci = NULL;

	if (ci->num_of_certs) {
		/* free all individual lists used */
		for (i = 0; i < ci->num_of_certs; i++) {
			curl_slist_free_all(ci->certinfo[i]);
			ci->certinfo[i] = NULL;
		}

		free(ci->certinfo); /* free the actual array too */
		ci->certinfo = NULL;
		ci->num_of_certs = 0;
	}
}

int vtls_init_certinfo(struct SessionHandle *data, int num)
{
//	struct curl_certinfo *ci = &data->info.certs;
	struct curl_certinfo *ci = NULL;
	struct curl_slist **table;

	/* Free any previous certificate information structures */
	vtls_free_certinfo(data);

	/* Allocate the required certificate information structures */
	table = calloc((size_t) num, sizeof(struct curl_slist *));
	if (!table)
		return CURLE_OUT_OF_MEMORY;

	ci->num_of_certs = num;
	ci->certinfo = table;

	return CURLE_OK;
}

/*
 * 'value' is NOT a zero terminated string
 */
int vtls_push_certinfo_len(struct SessionHandle *data,
	int certnum,
	const char *label,
	const char *value,
	size_t valuelen)
{
//	struct curl_certinfo * ci = &data->info.certs;
	struct curl_certinfo * ci = NULL;
	char * output;
	struct curl_slist * nl;
	int result = CURLE_OK;
	size_t labellen = strlen(label);
	size_t outlen = labellen + 1 + valuelen + 1; /* label:value\0 */

	output = malloc(outlen);
	if (!output)
		return CURLE_OUT_OF_MEMORY;

	/* sprintf the label and colon */
	snprintf(output, outlen, "%s:", label);

	/* memcpy the value (it might not be zero terminated) */
	memcpy(&output[labellen + 1], value, valuelen);

	/* zero terminate the output */
	output[labellen + 1 + valuelen] = 0;

//	nl = Curl_slist_append_nodup(ci->certinfo[certnum], output);
	if (!nl) {
		free(output);
		curl_slist_free_all(ci->certinfo[certnum]);
		result = CURLE_OUT_OF_MEMORY;
	}

	ci->certinfo[certnum] = nl;
	return result;
}

/*
 * This is a convenience function for push_certinfo_len that takes a zero
 * terminated value.
 */
int vtls_push_certinfo(struct SessionHandle *data,
	int certnum,
	const char *label,
	const char *value)
{
	size_t valuelen = strlen(value);

	return vtls_push_certinfo_len(data, certnum, label, value, valuelen);
}

int vtls_random(vtls_session_t *data, unsigned char *entropy, size_t length)
{
	return backend_random(data, entropy, length);
}

int vtls_md5sum(unsigned char *tmp, /* input */
	size_t tmplen,
	unsigned char *md5sum, /* output */
	size_t md5len)
{
	if (backend_md5sum(tmp, tmplen, md5sum, md5len) != 0) {
/*		MD5_context *MD5pw;

		MD5pw = Curl_MD5_init(Curl_DIGEST_MD5);
		Curl_MD5_update(MD5pw, tmp, curlx_uztoui(tmplen));
		Curl_MD5_final(MD5pw, md5sum);
 */
	}
}

/*
 * Check whether the SSL backend supports the status_request extension.
 */
int vtls_cert_status_request(void)
{
#ifdef curlssl_cert_status_request
	return curlssl_cert_status_request();
#else
	return 0;
#endif
}
