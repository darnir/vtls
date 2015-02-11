#ifndef _VTLS_BACKEND_H
#define _VTLS_BACKEND_H

/* Set the API backend definition to GnuTLS */
#define CURL_SSL_BACKEND CURLSSLBACKEND_GNUTLS

typedef struct {
	void *ssl_session;
	int sockfd;
	int use;
	int state;
} vtls_session_t;

/* API of backend TLS engines */
/*
#define curlssl_close_all(x) ((void)x)
#define curlssl_set_engine(x,y) ((void)x, (void)y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) ((void)x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) ((void)x, (struct curl_slist *)NULL)
#define curlssl_check_cxn(x) ((void)x, -1)
#define curlssl_data_pending(x,y) ((void)x, (void)y, 0)
*/
int backend_get_engine(void);
int backend_init(void);
int backend_deinit(void);
int backend_connect_nonblocking(struct connectdata *conn,
                              int sockindex,
                              int *done);
int backend_connect(struct connectdata *conn, int sockindex);
void backend_close(struct connectdata *conn, int sockindex);
int backend_shutdown(struct connectdata *conn, int sockindex);
void backend_session_free(void *ptr);
size_t backend_version(char *buffer, size_t size);
int backend_random(struct SessionHandle *data,
                     unsigned char *entropy,
                     size_t length);
void backend_md5sum(unsigned char *tmp, /* input */
                      size_t tmplen,
                      unsigned char *md5sum, /* output */
                      size_t md5len);
int backend_cert_status_request(void);

#endif /* _VTLS_BACKEND_H */
