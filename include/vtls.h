#ifndef _VTLS_VTLS_H
#define _VTLS_VTLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
// #include "curl_setup.h"

//#include "openssl.h"        /* OpenSSL versions */
//#include "gnutls.h"           /* GnuTLS versions */
//#include "nssg.h"           /* NSS versions */
//#include "gskit.h"          /* Global Secure ToolKit versions */
//#include "polarssl.h"       /* PolarSSL versions */
//#include "axtls.h"          /* axTLS versions */
//#include "cyassl.h"         /* CyaSSL versions */
//#include "schannel.h"       /* Schannel SSPI version */
//#include "curl_darwinssl.h" /* SecureTransport (Darwin) version */

#ifndef MAX_PINNED_PUBKEY_SIZE
#define MAX_PINNED_PUBKEY_SIZE 1048576 /* 1MB */
#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16 /* fixed size */
#endif

/* see http://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg-04 */
#define ALPN_HTTP_1_1_LENGTH 8
#define ALPN_HTTP_1_1 "http/1.1"

/* enum for the nonblocking SSL connection state machine */
typedef enum {
  ssl_connect_1,
  ssl_connect_2,
  ssl_connect_2_reading,
  ssl_connect_2_writing,
  ssl_connect_3,
  ssl_connect_done
} ssl_connect_state;

typedef enum {
  ssl_connection_none,
  ssl_connection_negotiating,
  ssl_connection_complete
} ssl_connection_state;

/* enum for the different supported SSL backends */
typedef enum {
	CURLSSLBACKEND_NONE = 0,
	CURLSSLBACKEND_OPENSSL = 1,
	CURLSSLBACKEND_GNUTLS = 2,
	CURLSSLBACKEND_NSS = 3,
	CURLSSLBACKEND_OBSOLETE4 = 4, /* Was QSOSSL. */
	CURLSSLBACKEND_GSKIT = 5,
	CURLSSLBACKEND_POLARSSL = 6,
	CURLSSLBACKEND_CYASSL = 7,
	CURLSSLBACKEND_SCHANNEL = 8,
	CURLSSLBACKEND_DARWINSSL = 9,
	CURLSSLBACKEND_AXTLS = 10
} curl_sslbackend;

typedef enum {
	CURLE_OK = 0,
	CURLE_UNSUPPORTED_PROTOCOL, /* 1 */
	CURLE_FAILED_INIT, /* 2 */
	CURLE_URL_MALFORMAT, /* 3 */
	CURLE_NOT_BUILT_IN, /* 4 - [was obsoleted in August 2007 for
                                    7.17.0, reused in April 2011 for 7.21.5] */
	CURLE_COULDNT_RESOLVE_PROXY, /* 5 */
	CURLE_COULDNT_RESOLVE_HOST, /* 6 */
	CURLE_COULDNT_CONNECT, /* 7 */
	CURLE_FTP_WEIRD_SERVER_REPLY, /* 8 */
	CURLE_REMOTE_ACCESS_DENIED, /* 9 a service was denied by the server
                                    due to lack of access - when login fails
                                    this is not returned. */
	CURLE_FTP_ACCEPT_FAILED, /* 10 - [was obsoleted in April 2006 for
                                    7.15.4, reused in Dec 2011 for 7.24.0]*/
	CURLE_FTP_WEIRD_PASS_REPLY, /* 11 */
	CURLE_FTP_ACCEPT_TIMEOUT, /* 12 - timeout occurred accepting server
                                    [was obsoleted in August 2007 for 7.17.0,
                                    reused in Dec 2011 for 7.24.0]*/
	CURLE_FTP_WEIRD_PASV_REPLY, /* 13 */
	CURLE_FTP_WEIRD_227_FORMAT, /* 14 */
	CURLE_FTP_CANT_GET_HOST, /* 15 */
	CURLE_HTTP2, /* 16 - A problem in the http2 framing layer.
                                    [was obsoleted in August 2007 for 7.17.0,
                                    reused in July 2014 for 7.38.0] */
	CURLE_FTP_COULDNT_SET_TYPE, /* 17 */
	CURLE_PARTIAL_FILE, /* 18 */
	CURLE_FTP_COULDNT_RETR_FILE, /* 19 */
	CURLE_OBSOLETE20, /* 20 - NOT USED */
	CURLE_QUOTE_ERROR, /* 21 - quote command failure */
	CURLE_HTTP_RETURNED_ERROR, /* 22 */
	CURLE_WRITE_ERROR, /* 23 */
	CURLE_OBSOLETE24, /* 24 - NOT USED */
	CURLE_UPLOAD_FAILED, /* 25 - failed upload "command" */
	CURLE_READ_ERROR, /* 26 - couldn't open/read from file */
	CURLE_OUT_OF_MEMORY, /* 27 */
	/* Note: CURLE_OUT_OF_MEMORY may sometimes indicate a conversion error
				instead of a memory allocation error if CURL_DOES_CONVERSIONS
				is defined
	 */
	CURLE_OPERATION_TIMEDOUT, /* 28 - the timeout time was reached */
	CURLE_OBSOLETE29, /* 29 - NOT USED */
	CURLE_FTP_PORT_FAILED, /* 30 - FTP PORT operation failed */
	CURLE_FTP_COULDNT_USE_REST, /* 31 - the REST command failed */
	CURLE_OBSOLETE32, /* 32 - NOT USED */
	CURLE_RANGE_ERROR, /* 33 - RANGE "command" didn't work */
	CURLE_HTTP_POST_ERROR, /* 34 */
	CURLE_SSL_CONNECT_ERROR, /* 35 - wrong when connecting with SSL */
	CURLE_BAD_DOWNLOAD_RESUME, /* 36 - couldn't resume download */
	CURLE_FILE_COULDNT_READ_FILE, /* 37 */
	CURLE_LDAP_CANNOT_BIND, /* 38 */
	CURLE_LDAP_SEARCH_FAILED, /* 39 */
	CURLE_OBSOLETE40, /* 40 - NOT USED */
	CURLE_FUNCTION_NOT_FOUND, /* 41 */
	CURLE_ABORTED_BY_CALLBACK, /* 42 */
	CURLE_BAD_FUNCTION_ARGUMENT, /* 43 */
	CURLE_OBSOLETE44, /* 44 - NOT USED */
	CURLE_INTERFACE_FAILED, /* 45 - CURLOPT_INTERFACE failed */
	CURLE_OBSOLETE46, /* 46 - NOT USED */
	CURLE_TOO_MANY_REDIRECTS, /* 47 - catch endless re-direct loops */
	CURLE_UNKNOWN_OPTION, /* 48 - User specified an unknown option */
	CURLE_TELNET_OPTION_SYNTAX, /* 49 - Malformed telnet option */
	CURLE_OBSOLETE50, /* 50 - NOT USED */
	CURLE_PEER_FAILED_VERIFICATION, /* 51 - peer's certificate or fingerprint
                                     wasn't verified fine */
	CURLE_GOT_NOTHING, /* 52 - when this is a specific error */
	CURLE_SSL_ENGINE_NOTFOUND, /* 53 - SSL crypto engine not found */
	CURLE_SSL_ENGINE_SETFAILED, /* 54 - can not set SSL crypto engine as
                                    default */
	CURLE_SEND_ERROR, /* 55 - failed sending network data */
	CURLE_RECV_ERROR, /* 56 - failure in receiving network data */
	CURLE_OBSOLETE57, /* 57 - NOT IN USE */
	CURLE_SSL_CERTPROBLEM, /* 58 - problem with the local certificate */
	CURLE_SSL_CIPHER, /* 59 - couldn't use specified cipher */
	CURLE_SSL_CACERT, /* 60 - problem with the CA cert (path?) */
	CURLE_BAD_CONTENT_ENCODING, /* 61 - Unrecognized/bad encoding */
	CURLE_LDAP_INVALID_URL, /* 62 - Invalid LDAP URL */
	CURLE_FILESIZE_EXCEEDED, /* 63 - Maximum file size exceeded */
	CURLE_USE_SSL_FAILED, /* 64 - Requested FTP SSL level failed */
	CURLE_SEND_FAIL_REWIND, /* 65 - Sending the data requires a rewind
                                    that failed */
	CURLE_SSL_ENGINE_INITFAILED, /* 66 - failed to initialise ENGINE */
	CURLE_LOGIN_DENIED, /* 67 - user, password or similar was not
                                    accepted and we failed to login */
	CURLE_TFTP_NOTFOUND, /* 68 - file not found on server */
	CURLE_TFTP_PERM, /* 69 - permission problem on server */
	CURLE_REMOTE_DISK_FULL, /* 70 - out of disk space on server */
	CURLE_TFTP_ILLEGAL, /* 71 - Illegal TFTP operation */
	CURLE_TFTP_UNKNOWNID, /* 72 - Unknown transfer ID */
	CURLE_REMOTE_FILE_EXISTS, /* 73 - File already exists */
	CURLE_TFTP_NOSUCHUSER, /* 74 - No such user */
	CURLE_CONV_FAILED, /* 75 - conversion failed */
	CURLE_CONV_REQD, /* 76 - caller must register conversion
                                    callbacks using curl_easy_setopt options
                                    CURLOPT_CONV_FROM_NETWORK_FUNCTION,
                                    CURLOPT_CONV_TO_NETWORK_FUNCTION, and
                                    CURLOPT_CONV_FROM_UTF8_FUNCTION */
	CURLE_SSL_CACERT_BADFILE, /* 77 - could not load CACERT file, missing
                                    or wrong format */
	CURLE_REMOTE_FILE_NOT_FOUND, /* 78 - remote file not found */
	CURLE_SSH, /* 79 - error from the SSH layer, somewhat
                                    generic so the error message will be of
                                    interest when this has happened */

	CURLE_SSL_SHUTDOWN_FAILED, /* 80 - Failed to shut down the SSL
                                    connection */
	CURLE_AGAIN, /* 81 - socket is not ready for send/recv,
                                    wait till it's ready and try again (Added
                                    in 7.18.2) */
	CURLE_SSL_CRL_BADFILE, /* 82 - could not load CRL file, missing or
                                    wrong format (Added in 7.19.0) */
	CURLE_SSL_ISSUER_ERROR, /* 83 - Issuer check failed.  (Added in
                                    7.19.0) */
	CURLE_FTP_PRET_FAILED, /* 84 - a PRET command failed */
	CURLE_RTSP_CSEQ_ERROR, /* 85 - mismatch of RTSP CSeq numbers */
	CURLE_RTSP_SESSION_ERROR, /* 86 - mismatch of RTSP Session Ids */
	CURLE_FTP_BAD_FILE_LIST, /* 87 - unable to parse FTP file list */
	CURLE_CHUNK_FAILED, /* 88 - chunk callback reported error */
	CURLE_NO_CONNECTION_AVAILABLE, /* 89 - No connection available, the
                                    session will be queued */
	CURLE_SSL_PINNEDPUBKEYNOTMATCH, /* 90 - specified pinned public key did not
                                     match */
	CURLE_SSL_INVALIDCERTSTATUS, /* 91 - invalid certificate status */
	CURL_LAST /* never use! */
} CURLcode;

enum {
  CURL_SSLVERSION_DEFAULT,
  CURL_SSLVERSION_TLSv1, /* TLS 1.x */
  CURL_SSLVERSION_SSLv2,
  CURL_SSLVERSION_SSLv3,
  CURL_SSLVERSION_TLSv1_0,
  CURL_SSLVERSION_TLSv1_1,
  CURL_SSLVERSION_TLSv1_2,

  CURL_SSLVERSION_LAST /* never use, keep last */
};

enum CURL_TLSAUTH {
  CURL_TLSAUTH_NONE,
  CURL_TLSAUTH_SRP,
  CURL_TLSAUTH_LAST /* never use, keep last */
};

enum {
	VTLS_CFG_TLS_VERSION	= 1,
	VTLS_CFG_VERIFY_PEER,
	VTLS_CFG_VERIFY_HOST,
	VTLS_CFG_VERIFY_STATUS,
	VTLS_CFG_CA_PATH,
	VTLS_CFG_CA_FILE,
	VTLS_CFG_CRL_FILE,
	VTLS_CFG_ISSUER_FILE,
	VTLS_CFG_RANDOM_FILE,
	VTLS_CFG_EGD_SOCKET,
	VTLS_CFG_CIPHER_LIST,
	VTLS_CFG_LOCK_CALLBACK,
	VTLS_CFG_CONNECT_TIMEOUT,
	VTLS_CFG_LAST
};

typedef struct ssl_config_data *ssl_config_data_t;
typedef struct _vtls_config_st vtls_config_t;
typedef struct _vtls_session_st vtls_session_t;

int vtls_config_init(vtls_config_t **config, ...);
int vtls_config_matches(const vtls_config_t *config1, const vtls_config_t *config2);
int vtls_config_clone(const vtls_config_t *source, vtls_config_t **dest);
void vtls_config_free(vtls_config_t *config);

int vtls_init(vtls_config_t *config);
void vtls_deinit(void);

int vtls_session_init(vtls_session_t **sess, vtls_config_t *config);
void vtls_session_deinit(vtls_session_t *sess);
int vtls_get_engine(void);
size_t vtls_version(char *buffer, size_t size);

int vtls_connect(vtls_session_t *sess, int sockfd, const char *hostname);
int vtls_connect_nonblocking(vtls_session_t *sess, int sockfd, int *done);
/* tell the SSL stuff to close down all open information regarding
	connections (and thus session ID caching etc) */
void vtls_close(vtls_session_t *sess);
int vtls_shutdown(vtls_session_t *sess);

/* get N random bytes into the buffer, return 0 if a find random is filled	in */
int vtls_md5sum(unsigned char *tmp, /* input */
	size_t tmplen,
	unsigned char *md5sum, /* output */
	size_t md5len);
int vtls_cert_status_request(void);

#define SSL_SHUTDOWN_TIMEOUT 10000 /* ms */

#endif /* _VTLS_VTLS_H */
