#include "metsrv.h"
#include "../../common/common.h"
#include "ssl_lib_setup.h"

// OpenSSL lib includes which contain references to the functions
#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

void setup_ssl_lib(SslLib* sslLib)
{
	dprintf("[SSL] setting up all SSL function pointers");
	sslLib->RAND_status = RAND_status;
	sslLib->RAND_add = RAND_add;
	sslLib->RAND_egd = RAND_egd;
	sslLib->ERR_get_state = ERR_get_state;
	sslLib->ERR_reason_error_string = ERR_reason_error_string;
	sslLib->ERR_clear_error = ERR_clear_error;
	sslLib->ERR_peek_last_error = ERR_peek_last_error;
	sslLib->SSL_get_current_compression = SSL_get_current_compression;
	sslLib->SSL_get_ex_data = SSL_get_ex_data;
	sslLib->SSL_set_SSL_CTX = SSL_set_SSL_CTX;
	sslLib->SSL_get_SSL_CTX = SSL_get_SSL_CTX;
	sslLib->SSL_CTX_load_verify_locations = SSL_CTX_load_verify_locations;
	sslLib->SSL_CTX_set_default_verify_paths = SSL_CTX_set_default_verify_paths;
	sslLib->SSL_get_shutdown = SSL_get_shutdown;
	sslLib->SSL_library_init = SSL_library_init;
	sslLib->SSL_set_accept_state = SSL_set_accept_state;
	sslLib->SSL_set_connect_state = SSL_set_connect_state;
	sslLib->SSL_shutdown = SSL_shutdown;
	sslLib->SSL_do_handshake = SSL_do_handshake;
	sslLib->TLSv1_method = TLSv1_method;
	sslLib->SSLv23_method = SSLv23_method;
	sslLib->SSLv3_method = SSLv3_method;
	sslLib->SSLv2_method = SSLv2_method;
	sslLib->SSL_get_version = SSL_get_version;
	sslLib->SSL_get_error = SSL_get_error;
	sslLib->SSL_CTX_callback_ctrl = SSL_CTX_callback_ctrl;
	sslLib->SSL_CTX_ctrl = SSL_CTX_ctrl;
	sslLib->SSL_free = SSL_free;
	sslLib->SSL_read = SSL_read;
	sslLib->SSL_write = SSL_write;
	sslLib->SSL_new = SSL_new;
	sslLib->SSL_CTX_set_session_id_context = SSL_CTX_set_session_id_context;
	sslLib->SSL_CTX_check_private_key = SSL_CTX_check_private_key;
	sslLib->SSL_CTX_set_default_passwd_cb = SSL_CTX_set_default_passwd_cb;
	sslLib->SSL_CTX_set_default_passwd_cb_userdata = SSL_CTX_set_default_passwd_cb_userdata;
	sslLib->SSL_set_ex_data = SSL_set_ex_data;
	sslLib->SSL_ctrl = SSL_ctrl;
	sslLib->SSL_CTX_set_verify = SSL_CTX_set_verify;
	sslLib->SSL_CTX_get_verify_mode = SSL_CTX_get_verify_mode;
	sslLib->SSL_get_peer_certificate = SSL_get_peer_certificate;
	sslLib->SSL_load_error_strings = SSL_load_error_strings;
	sslLib->SSL_CTX_use_certificate_chain_file = SSL_CTX_use_certificate_chain_file;
	sslLib->SSL_CTX_use_PrivateKey_file = SSL_CTX_use_PrivateKey_file;
	sslLib->SSL_set_read_ahead = SSL_set_read_ahead;
	sslLib->SSL_get_wbio = SSL_get_wbio;
	sslLib->SSL_get_rbio = SSL_get_rbio;
	sslLib->SSL_set_fd = SSL_set_fd;
	sslLib->SSL_pending = SSL_pending;
	sslLib->SSL_CIPHER_get_version = SSL_CIPHER_get_version;
	sslLib->SSL_CIPHER_get_name = SSL_CIPHER_get_name;
	sslLib->SSL_CIPHER_get_bits = SSL_CIPHER_get_bits;
	sslLib->SSL_get_current_cipher = SSL_get_current_cipher;
	sslLib->SSL_CTX_get_cert_store = SSL_CTX_get_cert_store;
	sslLib->SSL_CTX_free = SSL_CTX_free;
	sslLib->SSL_CTX_new = SSL_CTX_new;
	sslLib->SSL_CTX_set_cipher_list = SSL_CTX_set_cipher_list;
	sslLib->SSL_get_finished = SSL_get_finished;
	sslLib->SSL_get_peer_finished = SSL_get_peer_finished;
	sslLib->SSL_get_servername = SSL_get_servername;
	sslLib->PEM_read_bio = PEM_read_bio;
	sslLib->PEM_read_bio_X509 = PEM_read_bio_X509;
	sslLib->PEM_read_bio_X509_AUX = PEM_read_bio_X509_AUX;
	sslLib->X509_check_ca = X509_check_ca;
	sslLib->PEM_read_bio_DHparams = PEM_read_bio_DHparams;
	sslLib->X509V3_EXT_get = X509V3_EXT_get;
	sslLib->AUTHORITY_INFO_ACCESS_free = AUTHORITY_INFO_ACCESS_free;
	sslLib->GENERAL_NAME_print = GENERAL_NAME_print;
	sslLib->GENERAL_NAME_free = GENERAL_NAME_free;
	sslLib->X509_add_ext = X509_add_ext;
	sslLib->X509_get_ext_d2i = X509_get_ext_d2i;
	sslLib->X509_get_ext_by_NID = X509_get_ext_by_NID;
	sslLib->X509_NAME_ENTRY_get_object = X509_NAME_ENTRY_get_object;
	sslLib->X509_NAME_ENTRY_get_data = X509_NAME_ENTRY_get_data;
	sslLib->X509_NAME_get_entry = X509_NAME_get_entry;
	sslLib->X509_NAME_entry_count = X509_NAME_entry_count;
	sslLib->X509_get_subject_name = X509_get_subject_name;
	sslLib->X509_get_serialNumber = X509_get_serialNumber;
	sslLib->X509_get_ext = X509_get_ext;
	sslLib->X509_get_issuer_name = X509_get_issuer_name;
	sslLib->i2d_X509 = i2d_X509;
	sslLib->X509_free = X509_free;
	sslLib->sk_value = sk_value;
	sslLib->sk_num = sk_num;
	sslLib->sk_pop_free = sk_pop_free;
	sslLib->SSLeay_version = SSLeay_version;
	sslLib->SSLeay = SSLeay;
	sslLib->CRYPTO_num_locks = CRYPTO_num_locks;
	sslLib->CRYPTO_set_locking_callback = CRYPTO_set_locking_callback;
	sslLib->CRYPTO_set_id_callback = CRYPTO_set_id_callback;
	sslLib->CRYPTO_free = CRYPTO_free;
	sslLib->BIO_s_file = BIO_s_file;
	sslLib->BIO_new_file = BIO_new_file;
	sslLib->BIO_new = BIO_new;
	sslLib->BIO_free = BIO_free;
	sslLib->BIO_gets = BIO_gets;
	sslLib->BIO_ctrl = BIO_ctrl;
	sslLib->BIO_s_mem = BIO_s_mem;
	sslLib->BIO_new_mem_buf = BIO_new_mem_buf;
	sslLib->ASN1_OBJECT_free = ASN1_OBJECT_free;
	sslLib->ASN1_STRING_length = ASN1_STRING_length;
	sslLib->ASN1_STRING_data = ASN1_STRING_data;
	sslLib->i2a_ASN1_INTEGER = i2a_ASN1_INTEGER;
	sslLib->ASN1_INTEGER_get = ASN1_INTEGER_get;
	sslLib->ASN1_STRING_to_UTF8 = ASN1_STRING_to_UTF8;
	sslLib->ASN1_TIME_print = ASN1_TIME_print;
	sslLib->ASN1_item_d2i = ASN1_item_d2i;
	sslLib->OBJ_nid2obj = OBJ_nid2obj;
	sslLib->OBJ_nid2ln = OBJ_nid2ln;
	sslLib->OBJ_nid2sn = OBJ_nid2sn;
	sslLib->OBJ_obj2nid = OBJ_obj2nid;
	sslLib->OBJ_txt2obj = OBJ_txt2obj;
	sslLib->OBJ_obj2txt = OBJ_obj2txt;
	sslLib->OBJ_sn2nid = OBJ_sn2nid;
	sslLib->OPENSSL_add_all_algorithms_noconf = OPENSSL_add_all_algorithms_noconf;
	sslLib->EC_KEY_new_by_curve_name = EC_KEY_new_by_curve_name;
	sslLib->EC_KEY_free = EC_KEY_free;
	sslLib->DH_free = DH_free;
	sslLib->X509_STORE_add_cert = X509_STORE_add_cert;
	sslLib->X509_VERIFY_PARAM_set_flags = X509_VERIFY_PARAM_set_flags;
	sslLib->X509_VERIFY_PARAM_clear_flags = X509_VERIFY_PARAM_clear_flags;
	sslLib->X509_VERIFY_PARAM_get_flags = X509_VERIFY_PARAM_get_flags;
	sslLib->d2i_X509_bio = d2i_X509_bio;
	sslLib->X509_get_default_cert_dir = X509_get_default_cert_dir;
	sslLib->X509_get_default_cert_file = X509_get_default_cert_file;
	sslLib->X509_get_default_cert_dir_env = X509_get_default_cert_dir_env;
	sslLib->X509_get_default_cert_file_env = X509_get_default_cert_file_env;
	dprintf("[SSL] function pointers configured");
}
