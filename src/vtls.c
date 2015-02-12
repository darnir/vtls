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
#include <string.h>
#include <stdarg.h>

// #include "urldata.h"

#include <vtls.h> /* generic SSL protos etc */
#include "common.h"
#include "timeval.h"
#include "backend.h"

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

static const struct _vtls_config_st _default_config_static = {
	NULL, /* lock_callback: callback function for multithread library use */
	NULL, /* CApath: certificate directory (doesn't work on windows) */
	NULL, /* CAfile: certificate to verify peer against */
	NULL, /* CRLfile; CRL to check certificate revocation */
	NULL, /* issuercert: optional issuer certificate filename */
	NULL, /* random_file: path to file containing "random" data */
	NULL, /* egdsocket; path to file containing the EGD daemon socket */
	NULL, /* cipher_list; list of ciphers to use */
	NULL, /* username: TLS username (for, e.g., SRP) */
	NULL, /* password: TLS password (for, e.g., SRP) */
	CURL_TLSAUTH_NONE, /* TLS authentication type (default NONE) */
	CURL_SSLVERSION_TLSv1_0,	/* version: what TLS version the client wants to use */
	1, /* verifypeer: if peer verification is requested */
	1, /* verifyhost: if hostname matching is requested */
	1  /* verifystatus: if certificate status check is requested */
};
static const vtls_config_t *_default_config;

#define FETCH_AND_DUP(s) \
	if (((*config)->s = va_arg(args, const char *))) {\
		(*config)->s = strdup((*config)->s);\
		if (!(*config)->s)\
			return -2;\
	}

int vtls_config_init(vtls_config_t **config, ...)
{
	va_list args;
	int key;

	if (!config)
		return -1;

	if (!(*config = malloc(sizeof(**config))))
		return -2;

	// copy default values
	memcpy(*config, &_default_config_static, sizeof(_default_config_static));

	va_start(args, config);
	for (key = va_arg(args, int); key; key = va_arg(args, int)) {
		switch (key) {
		case VTLS_CFG_TLS_VERSION:
			(*config)->version = va_arg(args, int);
			break;
		case VTLS_CFG_VERIFY_PEER:
			(*config)->verifypeer = va_arg(args, int);
			break;
		case VTLS_CFG_VERIFY_HOST:
			(*config)->verifyhost = va_arg(args, int);
			break;
		case VTLS_CFG_VERIFY_STATUS:
			(*config)->verifystatus = va_arg(args, int);
			break;
		case VTLS_CFG_CA_PATH:
			FETCH_AND_DUP(CApath);
			break;
		case VTLS_CFG_CA_FILE:
			FETCH_AND_DUP(CAfile);
			break;
		case VTLS_CFG_CRL_FILE:
			FETCH_AND_DUP(CRLfile);
			break;
		case VTLS_CFG_ISSUER_FILE:
			FETCH_AND_DUP(issuercert);
			break;
		case VTLS_CFG_RANDOM_FILE:
			FETCH_AND_DUP(random_file);
			break;
		case VTLS_CFG_EGD_SOCKET:
			FETCH_AND_DUP(egdsocket);
			break;
		case VTLS_CFG_CIPHER_LIST:
			FETCH_AND_DUP(cipher_list);
			break;
		case VTLS_CFG_LOCK_CALLBACK:
			(*config)->lock_callback = va_arg(args, void(*)(int));
			break;
		default:
			/* unknown key */
			vtls_config_free(*config);
			return -3;
		}
	}
	va_end(args);

	return 0;
}
#undef FETCH_AND_DUP

int vtls_config_matches(const vtls_config_t *data, const vtls_config_t *needle)
{
	return ((data->version == needle->version) &&
		(data->verifypeer == needle->verifypeer) &&
		(data->verifyhost == needle->verifyhost) &&
		vtls_strcaseequal_ascii(data->CApath, needle->CApath) &&
		vtls_strcaseequal_ascii(data->CAfile, needle->CAfile) &&
		vtls_strcaseequal_ascii(data->random_file, needle->random_file) &&
		vtls_strcaseequal_ascii(data->egdsocket, needle->egdsocket) &&
		vtls_strcaseequal_ascii(data->cipher_list, needle->cipher_list));
}

#define DUP_MEMBER(s) \
	if (src->s) {\
		(*dst)->s = strdup(src->s);\
		if (!(*dst)->s)\
			return -2;\
	}

int vtls_config_clone(const vtls_config_t *src, vtls_config_t **dst)
{
	if (!dst)
		return -1;

	if (!(*dst = calloc(1, sizeof(**dst))))
		return -2;

	// copy config values
	memcpy(*dst, src, sizeof(*src));

	/* and dup the strings */
	DUP_MEMBER(CAfile);
	DUP_MEMBER(CApath);
	DUP_MEMBER(CRLfile);
	DUP_MEMBER(issuercert);
	DUP_MEMBER(random_file);
	DUP_MEMBER(egdsocket);
	DUP_MEMBER(cipher_list);

	return 0;
}
#undef DUP_MEMBER

void vtls_config_free(vtls_config_t *config)
{
	if (!config || config == &_default_config_static)
		return;

	xfree(config->CAfile);
	xfree(config->CApath);
	xfree(config->CRLfile);
	xfree(config->cipher_list);
	xfree(config->egdsocket);
	xfree(config->random_file);
	xfree(config->username);
	xfree(config->password);
	xfree(config);
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
 * @retval 0 SSL initialized successfully
 * @retval 1 error initializing SSL
 */
int vtls_init(vtls_config_t *config)
{
	int ret;

	if (config && config->lock_callback)
		config->lock_callback(1);

	/* make sure this is only done once */
	if (_init_vtls++)
		return 1;

	if (config)
		_default_config = config;
	else
		_default_config = &_default_config_static;

	ret = backend_init(config);

	if (config && config->lock_callback)
		config->lock_callback(0);

	return ret;
}

/* Global cleanup */
void vtls_deinit(void)
{
	if (--_init_vtls == 0) {
		/* only cleanup if we did a previous init */
		backend_deinit();
	}
}

int vtls_session_init(vtls_session_t **sess, vtls_config_t *config)
{
	if (!sess)
		return -1;

	if (!(*sess = calloc(1, sizeof(**sess))))
		return -2;

	(*sess)->config = config ? config : _default_config;

	return 0;
}

void vtls_session_deinit(vtls_session_t *sess)
{
	xfree(sess->hostname);
	xfree(sess);
}

int vtls_connect(vtls_session_t *sess, int sockfd, const char *hostname)
{
	/* mark this is being ssl-enabled from here on. */
	sess->use = 1;
	sess->state = ssl_connection_negotiating;
	sess->sockfd = sockfd;
	sess->hostname = strdup(hostname);

	return backend_connect(sess);
}

void vtls_close(vtls_session_t *sess)
{
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

int vtls_md5sum(unsigned char *tmp, /* input */
	size_t tmplen,
	unsigned char *md5sum, /* output */
	size_t md5len)
{
	int ret;

	if ((ret = backend_md5sum(tmp, tmplen, md5sum, md5len))) {
/*		MD5_context *MD5pw;

		MD5pw = Curl_MD5_init(Curl_DIGEST_MD5);
		Curl_MD5_update(MD5pw, tmp, curlx_uztoui(tmplen));
		Curl_MD5_final(MD5pw, md5sum);
 */
	}

	return ret;
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
