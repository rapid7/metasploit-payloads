/*!
 * @file python_ssl_bridge.c
 * @brief Bridge functions that wire SSL calls into metsrv's implementation
 * @remark This was created so that we didn't have to modify the source code to
 *         python itself. Instead, these functions work as a proxy to the existing
 *         instance of SSL that comes with metsrv. we could remove the calls and just
 *         work directly with gRemote, but modifying the python source means we have
 *         overhead every time we merge a new version of python. For this small effort
 *         it was worth doing it this way to make future merges easy.
 */
#include "../../common/common.h"
#include "openssl/err.h"
#include "python_main.h"

int RAND_status()
{
	return gRemote->ssl.RAND_status();
}

void RAND_add(const void *buf, int num, double entropy)
{
	gRemote->ssl.RAND_add(buf, num, entropy);
}

int RAND_egd(const char *path)
{
	return gRemote->ssl.RAND_egd(path);
}

ERR_STATE *ERR_get_state()
{
	return gRemote->ssl.ERR_get_state();
}

const char *ERR_reason_error_string(unsigned long e)
{
	return gRemote->ssl.ERR_reason_error_string(e);
}

void ERR_clear_error()
{
	gRemote->ssl.ERR_clear_error();
}

unsigned long ERR_peek_last_error()
{
	return gRemote->ssl.ERR_peek_last_error();
}

const COMP_METHOD *SSL_get_current_compression(SSL *s)
{
	return gRemote->ssl.SSL_get_current_compression(s);
}

void *SSL_get_ex_data(const SSL *ssl,int idx)
{
	return gRemote->ssl.SSL_get_ex_data(ssl, idx);
}

SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx)
{
	return gRemote->ssl.SSL_set_SSL_CTX(ssl, ctx);
}

SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl)
{
	return gRemote->ssl.SSL_get_SSL_CTX(ssl);
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath)
{
	return gRemote->ssl.SSL_CTX_load_verify_locations(ctx, CAfile, CApath);
}

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
	return gRemote->ssl.SSL_CTX_set_default_verify_paths(ctx);
}

int SSL_get_shutdown(const SSL *ssl)
{
	return gRemote->ssl.SSL_get_shutdown(ssl);
}

int SSL_library_init()
{
	return gRemote->ssl.SSL_library_init();
}

void SSL_set_accept_state(SSL *s)
{
	gRemote->ssl.SSL_set_accept_state(s);
}

void SSL_set_connect_state(SSL *s)
{
	gRemote->ssl.SSL_set_connect_state(s);
}

int SSL_shutdown(SSL *s)
{
	return gRemote->ssl.SSL_shutdown(s);
}

int SSL_do_handshake(SSL *s)
{
	return gRemote->ssl.SSL_do_handshake(s);
}

SSL_METHOD *TLSv1_method()
{
	return gRemote->ssl.TLSv1_method();
}

SSL_METHOD *SSLv23_method()
{
	return gRemote->ssl.SSLv23_method();
}

SSL_METHOD *SSLv3_method()
{
	return gRemote->ssl.SSLv3_method();
}

SSL_METHOD *SSLv2_method()
{
	return gRemote->ssl.SSLv2_method();
}

const char *SSL_get_version(const SSL *s)
{
	return gRemote->ssl.SSL_get_version(s);
}

int SSL_get_error(const SSL *s,int ret_code)
{
	return gRemote->ssl.SSL_get_error(s, ret_code);
}

long SSL_CTX_callback_ctrl(SSL_CTX * ctx, int cmd, void (*callback)(void))
{
	return gRemote->ssl.SSL_CTX_callback_ctrl(ctx, cmd, callback);
}

long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg)
{
	return gRemote->ssl.SSL_CTX_ctrl(ctx, cmd, larg, parg);
}

void SSL_free(SSL *ssl)
{
	gRemote->ssl.SSL_free(ssl);
}

int SSL_read(SSL *ssl,void *buf,int num)
{
	return gRemote->ssl.SSL_read(ssl, buf, num);
}

int SSL_write(SSL *ssl,const void *buf,int num)
{
	return gRemote->ssl.SSL_write(ssl, buf, num);
}

SSL* SSL_new(SSL_CTX *ctx)
{
	return gRemote->ssl.SSL_new(ctx);
}

int SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
	return gRemote->ssl.SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
}

int SSL_CTX_check_private_key(const SSL_CTX *ctx)
{
	return gRemote->ssl.SSL_CTX_check_private_key(ctx);
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
{
	gRemote->ssl.SSL_CTX_set_default_passwd_cb(ctx, cb);
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)
{
	gRemote->ssl.SSL_CTX_set_default_passwd_cb_userdata(ctx, u);
}

int SSL_set_ex_data(SSL *ssl, int idx, void *data)
{
	return gRemote->ssl.SSL_set_ex_data(ssl, idx, data);
}

long SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg)
{
	return gRemote->ssl.SSL_ctrl(ssl, cmd, larg, parg);
}

void SSL_CTX_set_verify(SSL_CTX *ctx,int mode, int (*callback)(int, X509_STORE_CTX *))
{
	gRemote->ssl.SSL_CTX_set_verify(ctx, mode, callback);
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
	return gRemote->ssl.SSL_CTX_get_verify_mode(ctx);
}

X509 * SSL_get_peer_certificate(const SSL *s)
{
	return gRemote->ssl.SSL_get_peer_certificate(s);
}

void SSL_load_error_strings()
{
	gRemote->ssl.SSL_load_error_strings();
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
	return gRemote->ssl.SSL_CTX_use_certificate_chain_file(ctx, file);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
	return gRemote->ssl.SSL_CTX_use_PrivateKey_file(ctx, file, type);
}

void SSL_set_read_ahead(SSL *s, int yes)
{
	gRemote->ssl.SSL_set_read_ahead(s, yes);
}

BIO * SSL_get_wbio(const SSL *s)
{
	return gRemote->ssl.SSL_get_wbio(s);
}

BIO * SSL_get_rbio(const SSL *s)
{
	return gRemote->ssl.SSL_get_rbio(s);
}

int SSL_set_fd(SSL *s, int fd)
{
	return gRemote->ssl.SSL_set_fd(s, fd);
}

int SSL_pending(const SSL *s)
{
	return gRemote->ssl.SSL_pending(s);
}

char * SSL_CIPHER_get_version(const SSL_CIPHER *c)
{
	return gRemote->ssl.SSL_CIPHER_get_version(c);
}

const char * SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
	return gRemote->ssl.SSL_CIPHER_get_name(c);
}

int SSL_CIPHER_get_bits(const SSL_CIPHER *c,int *alg_bits)
{
	return gRemote->ssl.SSL_CIPHER_get_bits(c, alg_bits);
}

SSL_CIPHER *SSL_get_current_cipher(const SSL *s)
{
	return gRemote->ssl.SSL_get_current_cipher(s);
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX * c)
{
	return gRemote->ssl.SSL_CTX_get_cert_store(c);
}

void SSL_CTX_free(SSL_CTX * c)
{
	gRemote->ssl.SSL_CTX_free(c);
}

SSL_CTX *SSL_CTX_new(SSL_METHOD *meth)
{
	return gRemote->ssl.SSL_CTX_new(meth);
}

int SSL_CTX_set_cipher_list(SSL_CTX * c,const char *str)
{
	return gRemote->ssl.SSL_CTX_set_cipher_list(c, str);
}

size_t SSL_get_finished(const SSL *s, void *buf, size_t count)
{
	return gRemote->ssl.SSL_get_finished(s, buf, count);
}

size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count)
{
	return gRemote->ssl.SSL_get_peer_finished(s, buf, count);
}

const char *SSL_get_servername(const SSL *s, const int type)
{
	return gRemote->ssl.SSL_get_servername(s, type);
}

int PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data,long *len)
{
	return gRemote->ssl.PEM_read_bio(bp, name, header, data, len);
}

X509* PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
	return gRemote->ssl.PEM_read_bio_X509(bp, x, cb, u);
}

X509* PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
	return gRemote->ssl.PEM_read_bio_X509_AUX(bp, x, cb, u);
}

int X509_check_ca(X509 *x)
{
	return gRemote->ssl.X509_check_ca(x);
}

DH* PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
	return gRemote->ssl.PEM_read_bio_DHparams(bp, x, cb, u);
}

X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext)
{
	return gRemote->ssl.X509V3_EXT_get(ext);
}

void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS* a)
{
	gRemote->ssl.AUTHORITY_INFO_ACCESS_free(a);
}

int GENERAL_NAME_print(BIO* out, GENERAL_NAME* gen)
{
	return gRemote->ssl.GENERAL_NAME_print(out, gen);
}

void GENERAL_NAME_free(GENERAL_NAME* gen)
{
	gRemote->ssl.GENERAL_NAME_free(gen);
}

int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc)
{
	return gRemote->ssl.X509_add_ext(x, ex, loc);
}

void* X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx)
{
	return gRemote->ssl.X509_get_ext_d2i(x, nid, crit, idx);
}

int X509_get_ext_by_NID(X509 *x, int nid, int lastpos)
{
	return gRemote->ssl.X509_get_ext_by_NID(x, nid, lastpos);
}

ASN1_OBJECT* X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne)
{
	return gRemote->ssl.X509_NAME_ENTRY_get_object(ne);
}

ASN1_STRING* X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne)
{
	return gRemote->ssl.X509_NAME_ENTRY_get_data(ne);
}

X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc)
{
	return gRemote->ssl.X509_NAME_get_entry(name, loc);
}

int X509_NAME_entry_count(X509_NAME *name)
{
	return gRemote->ssl.X509_NAME_entry_count(name);
}

X509_NAME* X509_get_subject_name(X509 *a)
{
	return gRemote->ssl.X509_get_subject_name(a);
}

ASN1_INTEGER* X509_get_serialNumber(X509 *x)
{
	return gRemote->ssl.X509_get_serialNumber(x);
}

X509_EXTENSION* X509_get_ext(X509 *x, int loc)
{
	return gRemote->ssl.X509_get_ext(x, loc);
}

X509_NAME* X509_get_issuer_name(X509 *a)
{
	return gRemote->ssl.X509_get_issuer_name(a);
}

void X509_free(X509* a)
{
	gRemote->ssl.X509_free(a);
}

int i2d_X509(X509* a, unsigned char** out)
{
	return gRemote->ssl.i2d_X509(a, out);
}

char* sk_value(const STACK* s, int i)
{
	return gRemote->ssl.sk_value(s, i);
}

int sk_num(const STACK* s)
{
	return gRemote->ssl.sk_num(s);
}


void sk_pop_free(STACK *st, void(*func)(void *))
{
	gRemote->ssl.sk_pop_free(st, func);
}

const char* SSLeay_version(int type)
{
	return gRemote->ssl.SSLeay_version(type);
}

unsigned long SSLeay()
{
	return gRemote->ssl.SSLeay();
}

int CRYPTO_num_locks()
{
	return gRemote->ssl.CRYPTO_num_locks();
}

void CRYPTO_set_locking_callback(void(*func)(int, int, const char *, int))
{
	gRemote->ssl.CRYPTO_set_locking_callback(func);
}

void CRYPTO_set_id_callback(unsigned long(*func)(void))
{
	gRemote->ssl.CRYPTO_set_id_callback(func);
}

void CRYPTO_free(void* p)
{
	gRemote->ssl.CRYPTO_free(p);
}

BIO_METHOD* BIO_s_file()
{
	return gRemote->ssl.BIO_s_file();
}

BIO *BIO_new_file(const char *filename, const char *mode)
{
	return gRemote->ssl.BIO_new_file(filename, mode);
}

BIO* BIO_new(BIO_METHOD *type)
{
	return gRemote->ssl.BIO_new(type);
}

int BIO_gets(BIO *bp, char *buf, int size)
{
	return gRemote->ssl.BIO_gets(bp, buf, size);
}

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
	return gRemote->ssl.BIO_ctrl(bp, cmd, larg, parg);
}

BIO_METHOD *BIO_s_mem(void)
{
	return gRemote->ssl.BIO_s_mem();
}

BIO* BIO_new_mem_buf(void *buf, int len)
{
	return gRemote->ssl.BIO_new_mem_buf(buf, len);
}

int BIO_free(BIO *a)
{
	return gRemote->ssl.BIO_free(a);
}

void ASN1_OBJECT_free(ASN1_OBJECT *a)
{
	gRemote->ssl.ASN1_OBJECT_free(a);
}

int ASN1_STRING_length(ASN1_STRING *x)
{
	return gRemote->ssl.ASN1_STRING_length(x);
}

unsigned char* ASN1_STRING_data(ASN1_STRING *x)
{
	return gRemote->ssl.ASN1_STRING_data(x);
}

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a)
{
	return gRemote->ssl.i2a_ASN1_INTEGER(bp, a);
}

long ASN1_INTEGER_get(ASN1_INTEGER *a)
{
	return gRemote->ssl.ASN1_INTEGER_get(a);
}

int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in)
{
	return gRemote->ssl.ASN1_STRING_to_UTF8(out, in);
}

int ASN1_TIME_print(BIO *fp, ASN1_TIME *a)
{
	return gRemote->ssl.ASN1_TIME_print(fp, a);
}

ASN1_VALUE* ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it)
{
	return gRemote->ssl.ASN1_item_d2i(val, in, len, it);
}

ASN1_OBJECT* OBJ_nid2obj(int n)
{
	return gRemote->ssl.OBJ_nid2obj(n);
}

const char* OBJ_nid2ln(int n)
{
	return gRemote->ssl.OBJ_nid2ln(n);
}

const char* OBJ_nid2sn(int n)
{
	return gRemote->ssl.OBJ_nid2sn(n);
}

int OBJ_obj2nid(const ASN1_OBJECT *o)
{
	return gRemote->ssl.OBJ_obj2nid(o);
}

ASN1_OBJECT* OBJ_txt2obj(const char *s, int no_name)
{
	return gRemote->ssl.OBJ_txt2obj(s, no_name);
}

int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)
{
	return gRemote->ssl.OBJ_obj2txt(buf, buf_len, a, no_name);
}

int OBJ_sn2nid(const char *s)
{
	return gRemote->ssl.OBJ_sn2nid(s);
}

void OPENSSL_add_all_algorithms_noconf()
{
	gRemote->ssl.OPENSSL_add_all_algorithms_noconf();
}

EC_KEY* EC_KEY_new_by_curve_name(int nid)
{
	return gRemote->ssl.EC_KEY_new_by_curve_name(nid);
}

void EC_KEY_free(EC_KEY* k)
{
	gRemote->ssl.EC_KEY_free(k);
}

void DH_free(DH *dh)
{
	gRemote->ssl.DH_free(dh);
}

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x)
{
	return gRemote->ssl.X509_STORE_add_cert(ctx, x);
}

int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags)
{
	return gRemote->ssl.X509_VERIFY_PARAM_set_flags(param, flags);
}

int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param, unsigned long flags)
{
	return gRemote->ssl.X509_VERIFY_PARAM_clear_flags(param, flags);
}

unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param)
{
	return gRemote->ssl.X509_VERIFY_PARAM_get_flags(param);
}

X509 *d2i_X509_bio(BIO *bp, X509 **x509)
{
	return gRemote->ssl.d2i_X509_bio(bp, x509);
}

const char* X509_get_default_cert_dir()
{
	return gRemote->ssl.X509_get_default_cert_dir();
}

const char* X509_get_default_cert_file()
{
	return gRemote->ssl.X509_get_default_cert_file();
}

const char* X509_get_default_cert_dir_env()
{
	return gRemote->ssl.X509_get_default_cert_dir_env();
}

const char* X509_get_default_cert_file_env()
{
	return gRemote->ssl.X509_get_default_cert_file_env();
}
