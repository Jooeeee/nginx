#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "vs_cwaf_sign_check.h"
#include "ngx_http_sign_module.h"

//#define _CONSOLE_DEBUG

#ifdef _CONSOLE_DEBUG
#define pin(format, args...) \
	printf("[%s-%d] "format,__func__,__LINE__,##args)
#else
#define pin(...)  
#endif

#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#endif
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#ifdef MIN
#undef MIN
#endif 
#define MIN(a,b) ((a)>(b)?(b):(a))


static ngx_int_t ngx_http_sign_set_check_tag(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_sign_set_decode_str(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_sign_set_decode_uri(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_sign_set_decode_cookie(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_sign_set_skip_sign (ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data);
static size_t _calc_dlen_base64(ngx_str_t *s, uintptr_t data);
static ngx_int_t _decode_base64(ngx_str_t *d, ngx_str_t *s, uintptr_t data);
static ngx_int_t _decode_url(ngx_str_t *d, ngx_str_t *s, uintptr_t data);
static ngx_int_t ngx_http_sign_add_variables(ngx_conf_t *cf);
static char *ngx_http_decode_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_sign_init(ngx_conf_t *cf);
static void *ngx_http_sign_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sign_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_sign_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_sign_init_module(ngx_cycle_t *cycle);
static void ngx_http_sign_exit_process(ngx_cycle_t *cycle);
static void ngx_http_sign_exit_master(ngx_cycle_t *cycle);

static ngx_uint_t sign_check_init_done = 0;
static ngx_conf_enum_t ngx_http_sign_enum_enable[] = {
	{ ngx_string("off"), NGX_HTTP_SIGN_OFF },
	{ ngx_string("on"), NGX_HTTP_SIGN_ON },
	{ ngx_null_string, 0}
};

static ngx_conf_enum_t ngx_http_sign_enum_block[] = {
	{ ngx_string("none"), NGX_HTTP_SIGN_BLOCK_NONE },
	{ ngx_string("high"), NGX_HTTP_SIGN_BLOCK_HIGH },
	{ ngx_string("medium"), NGX_HTTP_SIGN_BLOCK_MEDIUM },
	{ ngx_string("all"), NGX_HTTP_SIGN_BLOCK_ALL },
	{ ngx_null_string, 0}
};

static ngx_conf_enum_t ngx_http_sign_enum_log[] = {
	{ ngx_string("none"), NGX_HTTP_SIGN_LOG_NONE },
	{ ngx_string("block"), NGX_HTTP_SIGN_LOG_BLOCK },
	{ ngx_string("all"), NGX_HTTP_SIGN_LOG_ALL },
	{ ngx_null_string, 0}
};

struct {
	ngx_str_t s;
	ngx_uint_t f;
} decode_types [] = {
	{ ngx_string("base64"),NGX_HTTP_DECODE_BASE64 },
	{ ngx_string("url"),NGX_HTTP_DECODE_URL },
	{ ngx_string("utf7"),NGX_HTTP_DECODE_UTF7 },
	{ ngx_string("utf8"),NGX_HTTP_DECODE_UTF8 },
	{ ngx_string("hex"),NGX_HTTP_DECODE_HEX },
	{ ngx_string("json"),NGX_HTTP_DECODE_JSON },
	{ ngx_string("backslash"),NGX_HTTP_DECODE_BACKSLASH },
	{ ngx_string("xml"),NGX_HTTP_DECODE_XML },
	{ ngx_string("html"),NGX_HTTP_DECODE_HTML },
	{ ngx_string("phpseq"),NGX_HTTP_DECODE_PHPSEQ },
	{ ngx_string("unicode"),NGX_HTTP_DECODE_UNICODE },
};

static ngx_http_variable_t  ngx_http_sign_vars[] = {
	{ ngx_string("is_block"),
	  NULL,
	  ngx_http_sign_set_check_tag,
	  NGX_HTTP_SIGN_VAR_IS_BLOCK,
	  NGX_HTTP_VAR_NOCACHEABLE,
	  0 },
	{ ngx_string("is_attack"),
	  NULL,
  	  ngx_http_sign_set_check_tag,
	  NGX_HTTP_SIGN_VAR_IS_ATTACK,
	  NGX_HTTP_VAR_NOCACHEABLE,
	  0 },
	{ ngx_string("skip_sichk"), /* skip sign check flag */
	  ngx_http_sign_set_skip_sign,
	  NULL,
	  0,
	  NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_WEAK,
	  0 },
	{ ngx_string("decoded_uri"),
	  NULL,
	  ngx_http_sign_set_decode_uri,
	  NGX_HTTP_SIGN_VAR_DECODED_URI,
	  0,
	  0 },
	{ ngx_string("decoded_cookie"),
	  NULL,
	  ngx_http_sign_set_decode_cookie,
	  NGX_HTTP_SIGN_VAR_DECODED_COOKIE,
	  0,
	  0 },
	{ ngx_string("decoded_cookie_"),
	  NULL,
	  ngx_http_sign_set_decode_str,
	  NGX_HTTP_SIGN_VAR_DECODED_COOKIE_,
	  0,
	  0 },
	{ ngx_string("decoded_arg_"),
	  NULL,
	  ngx_http_sign_set_decode_str,
	  NGX_HTTP_SIGN_VAR_DECODED_ARG_,
	  0,
	  0 },
	{ ngx_string("decoded_user_agent"),
	  NULL,
	  ngx_http_sign_set_decode_str,
	  NGX_HTTP_SIGN_VAR_DECODED_USERAGENT,
	  0,
	  0 },
	{ ngx_string("decoded_referer"),
	  NULL,
	  ngx_http_sign_set_decode_str,
	  NGX_HTTP_SIGN_VAR_DECODED_REFERENCE,
	  0,
	  0 },
	{ ngx_string("decoded_x_forwarded_for"),
	  NULL,
	  ngx_http_sign_set_decode_str,
	  NGX_HTTP_SIGN_VAR_DECODED_XFORWARDF,
	  0,
	  0 },

	ngx_http_null_variable
};

static ngx_command_t ngx_http_sign_commands[] = {
	{ ngx_string("sign"),
	  NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_enum_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_sign_loc_conf_t, enable),
	  &ngx_http_sign_enum_enable },

	{ ngx_string("sign_block"),
	  NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_enum_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_sign_loc_conf_t, block),
	  &ngx_http_sign_enum_block },

	{ ngx_string("sign_log"),
	  NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_enum_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_sign_loc_conf_t, log),
	  &ngx_http_sign_enum_log },

	{ ngx_string("sign_check_body_size"),
	  NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_sign_loc_conf_t, check_body_size),
	  NULL },

	{ ngx_string("decode_type"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_http_decode_types_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_sign_loc_conf_t, decode),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_sign_module_ctx = {
	ngx_http_sign_add_variables,	/*  preconfiguration */
	ngx_http_sign_init,				/*  postconfiguration */

	NULL,							/*  create main configuration */
	NULL,							/*  init main configuration */

	NULL,							/*  create server configuration */
	NULL,							/*  merge server configuration */

	ngx_http_sign_create_loc_conf,	/*  create location configuration */
	ngx_http_sign_merge_loc_conf	/*  merge location configuration */
};


ngx_module_t ngx_http_sign_module = {
    NGX_MODULE_V1,
	&ngx_http_sign_module_ctx,	/* module context */
	ngx_http_sign_commands,		/* module directives */
	NGX_HTTP_MODULE,			/* module type */
	NULL,						/* init master */
	ngx_http_sign_init_module,	/* init module */
	ngx_http_sign_init_process,	/* init process */
	NULL,						/* init thread */
	NULL,						/* exit thread */
	ngx_http_sign_exit_process,	/* exit process */
	ngx_http_sign_exit_master,	/* exit master */
	NGX_MODULE_V1_PADDING
};

static struct {
	ngx_int_t (*decode)(ngx_str_t *d, ngx_str_t *s, uintptr_t data);
	size_t (*calc_dlen)(ngx_str_t *s, uintptr_t data);
} decoder[NGX_HTTP_DECODER_MAX] = {
	[NGX_HTTP_DECODER_BASE64] = {
		.decode	  = _decode_base64,
		.calc_dlen = _calc_dlen_base64,
	},
	[NGX_HTTP_DECODER_URL] = {
		.decode   = _decode_url,
		.calc_dlen = NULL,
	}
};

/* determine the order of multi-layer decoding, always end with -1 in path */
static ngx_int_t decode_path[NGX_HTTP_SIGN_VAR_DECODED_MAX][NGX_HTTP_DECODER_MAX] = {
	[0 ... NGX_HTTP_SIGN_VAR_DECODED_MAX-1] = {[0 ... NGX_HTTP_DECODER_MAX-1] = -1},
	[NGX_HTTP_SIGN_VAR_DECODED_URI] = { NGX_HTTP_DECODER_URL, NGX_HTTP_DECODER_BASE64, -1 }, /* url decode only for now */
	[NGX_HTTP_SIGN_VAR_DECODED_COOKIE] = { NGX_HTTP_DECODER_URL, NGX_HTTP_DECODER_BASE64, -1 },
};
static ngx_int_t default_decode_path[NGX_HTTP_DECODER_MAX] = {
	NGX_HTTP_DECODER_UTF7, NGX_HTTP_DECODER_URL, NGX_HTTP_DECODER_BASE64, -1
};
static inline void 
_trans_atoi(ngx_http_variable_value_t *vv, proto_data *pda, void *para)
{
	if(pda) {
#ifdef BYTE_ORDER_BE
		int t = atoi((char *)vv->data);
		pda->un.i = (t&0x000000ffU)<<24
			|(t&0x0000ff00U)<<8
			|(t&0x00ff0000U)>>8
			|(t&0xff000000U)>>16;
#else
		pda->un.i = atoi((char *)vv->data);
#endif
		pda->len = sizeof(int);
//		pin("[%s-%d]pda->un.i=%d, pda->len=%d\n",
//			   __func__,__LINE__,pda->un.i,pda->len);
	}
}

static inline void 
_trans_ip2int(ngx_http_variable_value_t *vv, proto_data *pda, void *para)
{
	int ip = 0;
	if (pda) {
#ifdef BYTE_ORDER_BE
		sscanf((char *)vv->data,"%hhu.%hhu.%hhu.%hhu",
			   &((u_char *)&ip)[0], &((u_char *)&ip)[1],
			   &((u_char *)&ip)[2], &((u_char *)&ip)[3]);
#else
		sscanf((char *)vv->data,"%hhu.%hhu.%hhu.%hhu",
			   &((u_char *)&ip)[3], &((u_char *)&ip)[2],
			   &((u_char *)&ip)[1], &((u_char *)&ip)[0]);
#endif
		pda->un.i = ip;
		pda->len = sizeof(ip);
		pin( "[%s-%d]: vv->data=%s ip=%d len=%d\n",
			   __func__,__LINE__,vv->data,pda->un.i,pda->len);
	}
}

static inline void
_trans_body_length(ngx_http_variable_value_t *vv, proto_data *pda, void *para)
{
	if (pda) {
		pda->un.p = (void *)vv->data;
		if (para) {
			pda->len  = MIN(vv->len,*(ngx_uint_t *)para);
			pin("check body size:%u, pda->len=%d\n",
				(unsigned int)*(ngx_uint_t *)para, pda->len);
		} else {
			pda->len = vv->len;
		}
	}
}

static inline ngx_int_t
_is_readable(ngx_str_t *s)
{
	size_t len = s->len;
	if(len < 1) {
		return NGX_ERROR;
	}

	while(--len == 0){
		if(!isprint(s->data[len])) {
			return NGX_ERROR;
		}
	}
	return NGX_OK;
}

static inline ngx_str_t
_decode_get_ori_headers_in(ngx_http_request_t *r, uintptr_t offset)
{
//	ngx_str_t 		s;
	ngx_table_elt_t	*h;

	h = *(ngx_table_elt_t **)((char *) r + offset);
	if (!h) {
		return (ngx_str_t)ngx_null_string;
	}

	return (ngx_str_t)h->value;
}

static inline ngx_str_t
_decode_get_ori_arg(ngx_http_request_t *r, uintptr_t data)
{
	/* TODO */
	return (ngx_str_t)ngx_null_string;
}

static inline ngx_str_t
_decode_get_ori_cookie(ngx_http_request_t *r, uintptr_t data)
{
	/* TODO */
	return (ngx_str_t)ngx_null_string;
}

static inline size_t 
_calc_dlen_base64(ngx_str_t *s, uintptr_t data)
{
	if (data == NGX_HTTP_SIGN_VAR_DECODED_ARG_ 
		|| data == NGX_HTTP_SIGN_VAR_DECODED_URI) {
		return s->len;
	} else {
		return ngx_base64_decoded_length(s->len);
	}
}

static ngx_int_t 
_decode_base64(ngx_str_t *d, ngx_str_t *s, uintptr_t data)
{
	u_char *p,*e;
	p = s->data;
	e = p + s->len;

	/* url base64 replace '+' '/' with '*' '_'  */
	if (data == NGX_HTTP_SIGN_VAR_DECODED_ARG_ 
		|| data == NGX_HTTP_SIGN_VAR_DECODED_URI) {
		while(p < e) {
			/* ALERT: special cases:
			 * 1.Bouncy Castle(replace = with . as complement) method will pass len check here
			 * 2.Common codes without complement will filter out here
			 * 3.Some other implentation will be lefted undecoded */
//			if (s->len%4!=0) {
//				return NGX_ERROR;
//			}

			if (!(isdigit(*p) || isalpha(*p))
				&& (*p != '_') && (*p != '-' )) {
				return NGX_ERROR;
			} else {
				p++;
			}
		}
		return ngx_decode_base64url(d, s) && _is_readable(d);
	} else {
		if (s->len%4!=0) {
			return NGX_ERROR;
		}
		while(p < e) {
			if (!(isdigit(*p) || isalpha(*p))
				&& !((*p == '=') && (p+2>=e))
				&& *p != '+' && *p != '/' ) {
				return NGX_ERROR;
			} else {
				p++;
			}
		}
		return ngx_decode_base64(d, s) && _is_readable(d);
	}
}

static ngx_int_t 
_decode_url(ngx_str_t *d, ngx_str_t *s, uintptr_t offset)
{
	char *dest = (char *)d->data;
	char *data = (char *)s->data;
	int dst_len = d->len;
	int src_len = s->len;
	int value;
	int c;
	int data_len = 0;

	while (src_len--) {
		if(data_len > dst_len)
			break;
		/* 
		if (*data == '+') {
			*dest = ' ';
		} else */ if (*data == '%' && src_len >= 2 && isxdigit((int) *(data + 1))
				   && isxdigit((int) *(data + 2))) {

			c = ((unsigned char *)(data+1))[0];
			if (isupper(c)) {
				c = tolower(c);
			}
			value = ((c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10)) * 16;
			c = ((unsigned char *)(data+1))[1];
			if (isupper(c)) {
				c = tolower(c);
			}
			value += (c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10);

			*dest = (char)value ;
			data += 2;
			src_len -= 2;
		} else {
			*dest = *data;
		}
		
		data++;
		dest++;
		data_len++;
	}
	*dest = '\0';
	d->len = dest-(char *)d->data;
	return NGX_OK;
}

static void 
ngx_http_sign_set_skip_sign (ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data)
{
	if (ngx_strncmp(v->data,"yes",MIN(v->len, sizeof("yes"))) == 0) {
		r->skip_sign_check = 1;
	} else {
		r->skip_sign_check = 0;
	}
}

static ngx_int_t 
ngx_http_sign_set_check_tag(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data)
{
	if (data == NGX_HTTP_SIGN_VAR_IS_BLOCK) {
		v->len = r->is_block ? sizeof("yes")-1 : sizeof("no")-1; 
		v->data = r->is_block ? (u_char *)"yes" : (u_char *)"no";
	} else if (data == NGX_HTTP_SIGN_VAR_IS_ATTACK) {
		v->len = r->is_attack ? sizeof("yes")-1 : sizeof("no")-1; 
		v->data = r->is_attack ? (u_char *)"yes" : (u_char *)"no";
	} else {
		return NGX_ERROR;
	}
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

/* 
 *enum    VS_XSS_VAR
 {
	VS_XSS_VAR_URL = 1,
	VS_XSS_VAR_COOKIE,
	VS_XSS_VAR_REFERENCE,
	VS_XSS_VAR_POST,
	VS_XSS_VAR_USERAGENT,
	VS_XSS_VAR_XFORWARD,
	VS_XSS_VAR_ANY,
	VS_XSS_VAR_MAX
};
SQL_TYPE
{
	VP_XSSQL_TYPE_URL=1,              // 输入数据类型：URL数据
	VP_XSSQL_TYPE_SEMI,               // 输入数据类型：以分号; 分割的通用数据(cook)
	VP_XSSQL_TYPE_AMPERSAND,          // 输入数据类型：以 & 号分割的数据(ref)
	VP_XSSQL_TYPE_DATA,               // 输入数据类型：无分割的数据(useragent,forward,expect)
	VP_XSSQL_TYPE_FORM,               // 输入数据类型：post报文的form数据(post)
	VP_XSSQL_TYPE_MULTIDATA,          // 输入数据类型：post报文的多媒体数据

	VP_XSSQL_TYPE_MAX
};

*/
/* header section default decoding */
static ngx_int_t 
ngx_http_sign_set_decode_str(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_str_t 					*dst,*src;
	ngx_int_t					*dpath;
	ngx_uint_t					i;
	ngx_http_sign_loc_conf_t 	*slcf;
	struct {
		ngx_str_t (*decode_get_ori)(ngx_http_request_t *r, uintptr_t offset);
		uintptr_t offset;
	} vars[] = {
		[NGX_HTTP_SIGN_VAR_DECODED_REFERENCE] = { _decode_get_ori_headers_in, offsetof(ngx_http_request_t, headers_in.referer) },
		[NGX_HTTP_SIGN_VAR_DECODED_USERAGENT] = { _decode_get_ori_headers_in, offsetof(ngx_http_request_t, headers_in.user_agent) },
		[NGX_HTTP_SIGN_VAR_DECODED_XFORWARDF] = { _decode_get_ori_headers_in, offsetof(ngx_http_request_t, headers_in.x_forwarded_for) },
		[NGX_HTTP_SIGN_VAR_DECODED_ARG_]      = { _decode_get_ori_arg, 0},
		[NGX_HTTP_SIGN_VAR_DECODED_COOKIE_]   = { _decode_get_ori_cookie, 0},
	};


	src = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
	if (src == NULL) {
		v->not_found = 1;
		return NGX_ERROR;
	}
	dst = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
	if (dst == NULL) {
		v->not_found = 1;
		if (src)
			ngx_pfree(r->pool, src);
		return NGX_ERROR;
	}
	dst->data = NULL;
	dst->len  = 0;

	slcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);
	
	*src = vars[data].decode_get_ori(r,vars[data].offset);
	//src==ngx_null_string, origin var not found;
	if (src->len == 0 && src->data == NULL) { 
		v->not_found = 1;
		if (src)
			ngx_pfree(r->pool, src);
		if (dst)
			ngx_pfree(r->pool, dst);
		return NGX_OK;
	}
	/* set origin var value as default */
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = src->data; //be careful about the mem pointed to by src->data; 
	v->len = src->len;

	/* chose decoding path */
	if (decode_path[data][0] != (ngx_int_t)-1) {
		dpath = decode_path[data];
	} else {
		dpath = default_decode_path;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[[SIGN]]==> Begin %s",__func__);

	/* decoding loops */
	for (i=0; i<NGX_HTTP_DECODER_MAX && dpath[i]!=-1; i++) {
		if ((1 << dpath[i]) & slcf->decode) {
			dst->len = decoder[dpath[i]].calc_dlen?decoder[dpath[i]].calc_dlen(src,data):src->len;
			dst->data = ngx_pnalloc(r->pool, dst->len);
			/* NOTICE: here seem to have succesive mem leak,
			 * but not to wory, ngx will auto reclaim this mem
			 * when to request destroy */

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
				"decode<%d> START src={%d,%p} dst={%d,%p}",dpath[i], 
				(int)src->len, src->data, (int)dst->len, dst->data);

			/* if one decoder failed, continue next in path */
			if (decoder[dpath[i]].decode && \
				decoder[dpath[i]].decode(dst, src, data) == NGX_OK) {
				*src = *dst;
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					  "decode<%d> OK, value: %V",dpath[i],dst);
			} else {
				*dst = *src;
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					  "decode<%d> ERR, value: %V",dpath[i],dst);
			}
		}
	}
	v->data = dst->data;
	v->len = dst->len;

	if (src)
		ngx_pfree(r->pool, src);
	if (dst)
		ngx_pfree(r->pool, dst);
	return NGX_OK;
}

/**
 * @brief uri decoding program
 *	   uri: <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<frag> 
 * example: foo://example.com:8042/path/to/file.html;key=value?name=ferret#nose
 *	 nginx:                       |r->uri(urldecoded)         |r->args(? excluded)
 *
 * params in r->uri will do b64 decode, r->args will do all decode in
 * decode_path[NGX_HTTP_SIGN_VAR_DECODED_URI]
 * @return NGX_OK if variable fetchable, otherwise NGX_ERROR 
 */
static ngx_int_t 
ngx_http_sign_set_decode_uri(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data)
{
	u_char						*p,*e,*u,*w,*a,ch,ach;
	ngx_str_t 					*dst,*src;
	ngx_int_t					*dpath,decode_comlex_uri = 1;
	ngx_uint_t					i,state,decoded;
	ngx_http_sign_loc_conf_t 	*slcf;
	enum {
		sw_start = 0,
		sw_equal,	//'='
		sw_semi,	//';'
		sw_quote, 	//'&'
		sw_end,		//end
	};

	dst = src = NULL;

	/* set origin var value as default */
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->len  = ((r->unparsed_uri.len+1)/2)*3; /* not a precise length */
	v->data = ngx_pnalloc(r->pool, v->len);
	if (v->data == NULL) {
		goto errout;
	}

	if (!decode_comlex_uri) {
		p = v->data;
		p = ngx_cpymem(p, r->uri.data, r->uri.len);
		if (r->args.len && r->args.data)
			p = ngx_cpymem(p, r->args.data, r->args.len);
		v->len = p-v->data;
		goto done;
	}

	src = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
	if (src == NULL) 
		goto errout;
	dst = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
	if (dst == NULL) 
		goto errout;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[[SIGN]]==> Begin %s",__func__);
	/* if param in r->uri, split param then decode */
	/* /path;a=1;b=2 */
	p = r->uri.data;
	e = p + r->uri.len;
	u = v->data;
	w = u + v->len;
	if ((p = ngx_strlchr(p, e,';'))) {
		dst->data = ngx_pnalloc(r->pool, r->uri.len);
		if (dst->data == NULL)
			goto errout;
		u = ngx_cpymem(u, r->uri.data, p-r->uri.data); //cpy "/path"

		while((a = p ? ngx_strlchr(p, e, '=') : NULL)){
			u = ngx_cpymem(u, p, a-p); //copy ";key"
			*u++ = *a++; //cpy '='
			p = ngx_strlchr(a, e, ';'); //search next ;

			src->len  = p ? p-a : e-a;
			src->data = a;
			dst->len  = src->len;
			if (decoder[NGX_HTTP_DECODER_BASE64].decode(dst,src,data) == NGX_ERROR) {
				u = ngx_cpymem(u, src->data, src->len);
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 
				   0, "b64 ERR, value: %*s\n",src->len, src->data);
			} else {	
				u = ngx_cpymem(u, dst->data, dst->len);
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 
				   0, "b64 OK, value: %*s\n",dst->len, dst->data);
			}
		}
		ngx_pfree(r->pool, dst->data);
	} else {
		u = ngx_cpymem(u, r->uri.data, r->uri.len);
	}

	/* parse args if there is any */
	if (r->args.data == NULL || r->args.len == 0) {
		v->len = u-v->data;
		goto done;
	}

	slcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);

	/* chose decoding path */
	if (decode_path[data][0] != (ngx_int_t)-1) {
		dpath = decode_path[data];
	} else {
		dpath = default_decode_path;
	}

	/* decode r->args 
	 * example: a=value_a&b=dmFsdWVfYg%3d%3d
	 * */
	*u++ = '?'; //manually add '?'
	p = r->args.data;
	e = p + r->args.len;
	a = NULL;
	src->len = 0;
	state = sw_start;
	decoded = 0;
	for(ch = *p; p < e && /* likely */u < w; ch=*++p) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ch %c", ch);
		switch(state) {
		case sw_start:
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[state] start");
			if ((ch >= '0' && ch <= '9')
				|| (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')) {
				*u++ = ch;
			} else if (ch == '=') {
				state = sw_equal;
				*u++ = ch;
			} else if (ch == '&') {
				/* unusal branch  */
				*u++ = ch;
			} else if (ch == '%') {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 
					0, "unexpected % in key str,possible url encoded");
			}
			/* abnormal char, discard */
			break;
		case sw_equal:
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[state] equal");
			if (ch == '&') {
				state = sw_quote;
				ach = ch;
			} else {
				src->len ++;
				if (!a) 
					a = p;
			}
			if (p+1 != e)
				break;
			else
				ach = ch = 0;
			/* else fall-through */
		case sw_quote:
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[state] quote");
			src->data = a;

			if (src->len==0||a==NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log,
					 0, "possible empty value str");;
				goto errout;
			}

			/* decoding loops for each arg seg*/
			for (i=0; i<NGX_HTTP_DECODER_MAX && dpath[i]!=-1; i++) {
				if ((1<<dpath[i]) & slcf->decode) {
					if (decoder[dpath[i]].calc_dlen) {
						dst->len = decoder[dpath[i]].calc_dlen(src,data);
						ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
							"i=%d,dpath[i]=%d,decoder[%d].calc_dlen=%p,dst->len=%d",
							(int)i,(int)dpath[i],(int)dpath[i],decoder[dpath[i]].calc_dlen,(int)dst->len);
					} else {
						dst->len = src->len;
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "dst->len=%d", (int)dst->len);
					}
					if (dst->len > (size_t)(w-u)) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log,
							0, "not enough space for decoding[%d], calculated len=%d,"
							" v->data left=%d",(int)i, (int)dst->len, (int)(w-u)); 
						goto errout;
					}
					/* NOTICE: here seem to have succesive mem leak,
					 * but not to wory, ngx will auto reclaim this mem
					 * when to request destroy */
					dst->data = ngx_pnalloc(r->pool, dst->len);

					ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
						"decode<%d> START, src={%d,%p} dst={%d,%p}",dpath[i], 
						(int)src->len, src->data, (int)dst->len, dst->data);

					/* if one decoder failed, continue next in path */
					if (decoder[dpath[i]].decode  && \
						decoder[dpath[i]].decode(dst, src, data) == NGX_OK) {
						*src = *dst;
						ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
							  "decode<%d> OK, value: %V",dpath[i],dst);
					} else {
						*dst = *src;
						ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
							  "decode<%d> ERR, value: %V",dpath[i],dst);
					}
					decoded = 1;
				}
			}

			if (decoded) {
				u = ngx_cpymem(u, dst->data, dst->len);
			} else {
				u = ngx_cpymem(u, src->data, src->len);
			}
			if(ach)
				*u++=ach;
			if(ch)
				*u++=ch;

			a = NULL;
			ach = 0;
			decoded = 0;
			src->len = 0;
			src->data = NULL;
			state = sw_start;
			break;
		default:
			break;
		}
	}
	v->len = u-v->data;

done:
	return NGX_OK;
errout:
	v->not_found = 1;
	v->valid = 0;
	if (v->data && v->len)
		ngx_pfree(r->pool, v->data);
	if (dst && dst->data)
		ngx_pfree(r->pool, dst->data);
	if (src)
		ngx_pfree(r->pool, src);
	if (dst)
		ngx_pfree(r->pool, dst);

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0 ,"%s failed!", __func__);
	return NGX_ERROR;
}

static ngx_int_t 
ngx_http_sign_set_decode_cookie(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data)
{
	size_t			len;
    u_char			*p, *end, *pp, *pe, sep,*psep, *peq;
	ngx_int_t		*dpath;
	ngx_str_t		*src,*dst;
    ngx_uint_t		i, n, j, decoded;
    ngx_array_t		*a;
    ngx_table_elt_t	**h;
	ngx_http_sign_loc_conf_t *slcf;

    a = &r->headers_in.cookies;
    n = a->nelts;
    h = a->elts;
    len = 0;
	sep = ';';

    for (i = 0; i < n; i++) {
        if (h[i]->hash == 0) {
            continue;
        }
        len += h[i]->value.len + 2;
    }

    if (len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
//    len -= 2;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

	src = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
	if (src == NULL) {
		return NGX_ERROR;
	}
	dst = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
	if (dst == NULL){
		if (src) ngx_pfree(r->pool, src);
		return NGX_ERROR;
	}
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
		if (src) ngx_pfree(r->pool, src);
		if (dst) ngx_pfree(r->pool, dst);
        return NGX_ERROR;
    }

	slcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);

    v->len = len;
    v->data = p;
    end = p + len;

	if (decode_path[data][0] != (ngx_int_t)-1) {
		dpath = decode_path[data];
	} else {
		dpath = default_decode_path;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[[SIGN]]==> Begin %s",__func__);

    for (i = 0; i < n; i++) {
        if (h[i]->hash == 0) {
            continue;
        }
		
		if (slcf->decode && dpath[0] != -1) {
			pp = h[i]->value.data;
			pe = pp + h[i]->value.len;
			peq = psep = NULL;
			while(pp<pe){
				psep = ngx_strlchr(pp, pe, ';');
				/* split value from pairs */
				if (!psep)
					psep = pe;
				if ((peq = ngx_strlchr(pp, psep, '='))==NULL) { //search first '=' in name-value pair
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 
						0, "no = in %*s",((psep?psep:pe)-pp),pp);
					break;
				}
				peq += 1; //escape '='
				p = ngx_cpymem(p, pp, peq-pp); //cpy "name="
				src->data = peq;
				src->len = (size_t)(psep-peq);
				decoded = 0;
				ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
					"[name=value]:%*s%*s", (peq-pp),pp,(psep-peq),peq);

				/* multi-layer decoding */
				for (j=0; j<NGX_HTTP_DECODER_MAX && dpath[j]!=-1; j++) {
					if ((1 << dpath[j]) & slcf->decode) {
						/* NOTICE: here seem to have succesive mem leak,
						 * but not to wory, ngx will auto reclaim this mem
						 * when to request destroy */
						dst->len = decoder[dpath[j]].calc_dlen?decoder[dpath[j]].calc_dlen(src,data):src->len;
						dst->data = ngx_pnalloc(r->pool, dst->len);

						ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
							"decode<%d> START src={%d,%p} dst={%d,%p}",dpath[j], 
							(int)src->len, src->data, (int)dst->len, dst->data);

						/* if one decoder failed, continue next in path */
						if (decoder[dpath[i]].decode  && \
							decoder[dpath[j]].decode(dst, src, data) == NGX_OK) {
							*src = *dst;
							ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
								  "decode<%d> OK, value: %V",dpath[j],dst);
						} else {
							*dst = *src;
							ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
								  "decode<%d> ERR, value: %V",dpath[j],dst);
						}
						decoded = 1;
					}
				}
				/* copy to target space */
				if (decoded) {
					p = ngx_cpymem(p, dst->data, dst->len);
				} else {
					p = ngx_cpymem(p, peq, (size_t)(psep-pp));
				}
				if (p < end && psep < pe) *p++ = sep;
				pp = psep+1;
			}
		} else {
			p = ngx_copy(p, h[i]->value.data, h[i]->value.len);
			if (p<end) *p++ = sep; 
			if (p<end) *p++ = ' ';
		}

        if (p >= end) {
            break;
        }
    }

	v->len = (size_t)(p-v->data);
	if (src) ngx_pfree(r->pool, src);
	if (dst) ngx_pfree(r->pool, dst);
	return NGX_OK;
}

static ngx_int_t
ngx_http_sign_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_sign_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

		*var = *v;
    }

    return NGX_OK;
}

static char *
ngx_http_decode_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	u_char 		*p,*pp;
	ngx_str_t	*v;
	ngx_uint_t	*d,i;

	d = (ngx_uint_t *)((char *)conf + cmd->offset);
	v = cf->args->elts;
	pin("value:%*s\n",v[1].len, v[1].data);

	if (v[1].len == 1 && v[1].data[0] == '*') {
		*d |= NGX_HTTP_DECODE_BASE64 | NGX_HTTP_DECODE_URL
			| NGX_HTTP_DECODE_UTF7	| NGX_HTTP_DECODE_UTF8
			| NGX_HTTP_DECODE_HEX	| NGX_HTTP_DECODE_JSON
			| NGX_HTTP_DECODE_BACKSLASH| NGX_HTTP_DECODE_XML
			| NGX_HTTP_DECODE_HTML	| NGX_HTTP_DECODE_PHPSEQ
			| NGX_HTTP_DECODE_UNICODE;
		return NGX_CONF_OK;
	}

	for (pp=p=v[1].data; (ngx_uint_t)(p-v[1].data)<=v[1].len; p++) {
		if (*p != ',' && p!=v[1].data+v[1].len) 
			continue;

		if (p-pp <= 0)
			continue;

		ngx_strlow(pp,pp,(p-pp));
		for (i=0; i<ARRAY_SIZE(decode_types);i++) {
			if (0 == ngx_strncmp(pp, decode_types[i].s.data, p-pp)) {
				pin("hit i=%d, pp=%s f=%d\n",(int)i, pp, (int)decode_types[i].f);
				*d |= decode_types[i].f;
				break;
			}
		}
		if (i==ARRAY_SIZE(decode_types)) {
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, 
				"undefined decode type %*s\n",p-pp,pp);
			return NGX_CONF_ERROR;
		}
		pp = p+1;
	}
	pin("decode_type=%x\n",*d);
	return NGX_CONF_OK;
}

static void *
ngx_http_sign_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_sign_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sign_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET_UINT;
	conf->block = NGX_CONF_UNSET_UINT;
	conf->log  = NGX_CONF_UNSET_UINT;
	conf->check_body_size = NGX_CONF_UNSET_SIZE;

	return conf;
}

static char * 
ngx_http_sign_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_sign_loc_conf_t *prev = parent;
	ngx_http_sign_loc_conf_t *conf = child;

	ngx_conf_merge_uint_value(conf->enable, prev->enable, NGX_HTTP_SIGN_OFF);
	ngx_conf_merge_uint_value(conf->block, prev->block, NGX_HTTP_SIGN_BLOCK_NONE);
	ngx_conf_merge_uint_value(conf->log, prev->log, NGX_HTTP_SIGN_LOG_NONE);
	ngx_conf_merge_size_value(conf->check_body_size, prev->check_body_size, (size_t)0);

	return NGX_CONF_OK;
}

static inline void
ngx_http_sign_get_headers(ngx_http_request_t *r, u_char **s, u_char **e)
{
	ngx_uint_t			i;
	ngx_buf_t			*b;
	ngx_list_part_t		*part;
	ngx_table_elt_t		*head;

	if (!r ||!s ||!e) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[[SIGN]]==> in param %s is NULL",r?(s?"e":"s"):"r");
		return;	
	}

	/* alloc memory for headers, size of 4k for the moment */
	b = ngx_create_temp_buf(r->pool, 4*1024);
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[[SIGN]]==> create tempbuf failed");
		return;
	}

	b->last = ngx_copy(b->last, r->request_line.data, r->request_line.len);
	*b->last++ = CR; *b->last++ = LF;

	part = &r->headers_in.headers.part;
	head = part->elts;
	for (i = 0; /* void */; i++){
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			head = part->elts;
			i = 0;
		}
		/* for bugxxxx; prevention of memory currption */
		if (b->last+head[i].key.len+head[i].value.len+2 >= b->end){
			if (b->last + 5 < b->end) {
				*b->last++ = '.';
				*b->last++ = '.';
				*b->last++ = '.';
			}
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log,
						   0, "No space in buffer, escape remain headers");
			break;
		}

		b->last = ngx_copy(b->last, head[i].key.data, head[i].key.len);
		*b->last++ = ':'; *b->last++ = ' ';
		b->last = ngx_copy(b->last, head[i].value.data, head[i].value.len);
		*b->last++ = CR; *b->last++ = LF;
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP,r->connection->log, 0,
					  "[[SIGN]]==> header: %V: %V", &head[i].key, &head[i].value);
	}
	*b->last++ = CR; *b->last = LF;

	*s = b->pos;
	*e = b->last;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP,r->connection->log, 
				  0, "[[SIGN]]==> request headers: \n %*s",(int)(*e - *s), *s);
}

static inline ngx_int_t
ngx_http_sign_check(ngx_http_request_t *r, ngx_http_sign_var_t *vars, ngx_uint_t num)
{
	off_t						headers_len;
	u_char						*headers_start;
	u_char						*headers_end;
	proto_data 					*pda;
	ngx_int_t					ret,if_block;
	ngx_uint_t					key,i,x;
	ngx_str_t					str;
	ngx_http_variable_value_t	*vv;
	ngx_http_sign_loc_conf_t 	*lcf;
	ngx_http_core_loc_conf_t	*clcf;

	lcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	sign_check_set_conf(SIGN_CONF_SET_LOG_THRESHOLD, (void *)lcf->log); 
	sign_check_set_conf(SIGN_CONF_SET_BLOCK_THRESHOLD, (void *)lcf->block); 
	sign_check_set_conf(SIGN_CONF_SET_BLOCK_TYPE, (void *)clcf->block_method);

	pda = ngx_pcalloc(r->pool, sizeof(proto_data) * num);
	for (i=0,x=0; i<num && x<=i; i++) {
		str.data = ngx_pstrdup(r->pool, &vars[i].s);
		str.len	 = vars[i].s.len;
		key = ngx_hash_strlow(str.data, str.data, str.len);
		vv	= ngx_http_get_variable(r, &str, key);
		if (vv == NULL || vv->not_found || !vv->valid) {
			continue;
		}

		if (vars[i].trans) {
			vars[i].trans(vv, (pda+x), vars->para);
		} else {
			pda[x].un.p = (void *)vv->data;
			pda[x].len = vv->len;
		}
		pda[x].id = vars[i].id;

		ngx_log_debug5(NGX_LOG_DEBUG_HTTP,r->connection->log, 0,
					   "[[SIGN]]==> %i:id[%d] %V: %v(%d)", x, pda[x].id, &str, vv, vv->len);
		x++;
		ngx_pfree(r->pool, str.data);
	}

	ret = 0;
	if_block = (ngx_int_t)-1;
	ret = (ngx_int_t)sign_check_check(pda, x, (int *)&if_block);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, 
				  "[[SIGN]]==> ret=%i if_block=%d\n", ret, (int)if_block);
	if (ret > 0) {
		if (lcf->log) {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log, 0, "[[SIGN]]==> send log\n");

			headers_start = headers_end = NULL;
			ngx_http_sign_get_headers(r, &headers_start, &headers_end);
			headers_len = (headers_start && headers_end \
						   && headers_start < headers_end) \
						  ? headers_end - headers_start : 0;

			sign_check_send_log(headers_start, headers_len);
		}
		r->is_attack = 1;

		switch(clcf->block_method) {
		case NGX_HTTP_BLOCK_METHOD_NONE:
			break;
		case NGX_HTTP_BLOCK_METHOD_REDIRECT:
			/* TODO: */
			break;
		case NGX_HTTP_BLOCK_METHOD_ERRCODE:
			if ((((int)if_block) == 1) && ((int)lcf->block>0)) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[[SIGN]]==> return 403\n");
				ngx_pfree(r->pool, pda);
				r->is_block = 1;
				return NGX_HTTP_FORBIDDEN;
			}
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[[SIGN]]==> unknown block method\n");
			break;
		}
		
	} else if (ret < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
					  "[[SIGN]]==> sign_check failed");
	}

	ngx_pfree(r->pool, pda);
	return NGX_DECLINED;
}

static void
ngx_http_sign_body_handler(ngx_http_request_t *r)
{
	ngx_int_t					rc;
	ngx_http_sign_loc_conf_t 	*lcf=ngx_http_get_module_loc_conf(r, ngx_http_sign_module);
	ngx_http_sign_var_t			names[] = {
		{ ngx_string("http_host"), VI_HTTP_HOST, NULL, NULL},
		{ ngx_string("http_user_agent"), VI_HTTP_USER_AGENT, NULL, NULL},
		{ ngx_string("http_referer"), VI_HTTP_REFERENCE, NULL, NULL},
#if (NGX_HTTP_X_FORWARDED_FOR)
		{ ngx_string("http_x_forwared_for"), VI_HTTP_FORWARDEDFOR, NULL, NULL},
#endif
		{ ngx_string("http_cookie"), VI_HTTP_COOKIE_STR, NULL, NULL},
		{ ngx_string("http_x_powered_by"), VI_HTTP_POWEREDBY, NULL, NULL},
		{ ngx_string("http_if_none_match"), VI_HTTP_IF_NONE_MATCH, NULL, NULL},
		{ ngx_string("http_if_match"), VI_HTTP_IF_MATCH, NULL, NULL},
		{ ngx_string("http_accept"), VI_HTTP_ACCEPT, NULL, NULL},
		{ ngx_string("http_accept_encoding"), VI_HTTP_ACCEPT_ENCODING, NULL, NULL},
		{ ngx_string("http_accept_language"), VI_HTTP_ACCEPT_LANGUAGE, NULL, NULL},
		{ ngx_string("http_expect"), VI_HTTP_EXPECT, NULL, NULL},
		{ ngx_string("http_cache_control"), VI_HTTP_CACHE_CONTROL, NULL, NULL},
		{ ngx_string("http_connection"), VI_HTTP_CONNECTION, NULL, NULL},
		{ ngx_string("content_length"), VI_HTTP_CONTENT_LENGTH, _trans_atoi, NULL},
		{ ngx_string("content_type"), VI_HTTP_CONTENT_TYPE, NULL, NULL},
		{ ngx_string("remote_user"), VI_HTTP_USER, NULL, NULL},
		{ ngx_string("remote_addr"), VI_IP_SIP, _trans_ip2int, NULL},
		{ ngx_string("remote_port"), VI_TDP_SPORT, _trans_atoi, NULL},
		{ ngx_string("server_addr"), VI_IP_DIP, _trans_ip2int, NULL},
		{ ngx_string("server_port"), VI_TDP_DPORT, _trans_atoi, NULL},
		{ ngx_string("server_protocol"), VI_HTTP_VERSION, NULL, NULL},
		{ ngx_string("request_uri"), VI_HTTP_URL_STR, NULL, NULL}, 
		{ ngx_string("request_method"), VI_HTTP_METHOD, NULL, NULL}, 
		{ ngx_string("query_string"), VI_HTTP_URL_QUERY, NULL, NULL},
		{ ngx_string("decoded_uri"), VI_HTTP_URL, NULL, NULL},
		{ ngx_string("decoded_cookie"),VI_HTTP_COOKIE, NULL, NULL},
		{ ngx_string("decoded_user_agent"),VI_HTTP_USER_AGENT, NULL, NULL}, //overwrite http_user_agent above
		{ ngx_string("request_body"), VI_HTTP_MSGBODY, 
			_trans_body_length, (void *)&lcf->check_body_size},
	};

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log, 0, "[[SIGN]]==> IN body check handler");
	rc = ngx_http_sign_check(r, names, ARRAY_SIZE(names));
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		ngx_http_finalize_request(r, rc);
	} else {
		ngx_http_finalize_request(r, NGX_OK);
	}
}

#define NGX_HTTP_VAR_NUM 128
static ngx_int_t
ngx_http_sign_handler(ngx_http_request_t *r)
{
	ngx_int_t					rc;
	ngx_http_sign_loc_conf_t 	*lcf;
	ngx_http_core_loc_conf_t	*clcf;
	ngx_http_sign_var_t names[] = {
		{ ngx_string("http_host"), VI_HTTP_HOST, NULL, NULL},
		{ ngx_string("http_user_agent"), VI_HTTP_USER_AGENT, NULL, NULL},
		{ ngx_string("http_referer"), VI_HTTP_REFERENCE, NULL, NULL},
#if (NGX_HTTP_X_FORWARDED_FOR)
		{ ngx_string("http_x_forwared_for"), VI_HTTP_FORWARDEDFOR, NULL, NULL},
#endif
		{ ngx_string("http_cookie"), VI_HTTP_COOKIE_STR, NULL, NULL},
		{ ngx_string("http_x_powered_by"), VI_HTTP_POWEREDBY, NULL, NULL},
		{ ngx_string("http_if_none_match"), VI_HTTP_IF_NONE_MATCH, NULL, NULL},
		{ ngx_string("http_if_match"), VI_HTTP_IF_MATCH, NULL, NULL},
		{ ngx_string("http_accept"), VI_HTTP_ACCEPT, NULL, NULL},
		{ ngx_string("http_accept_encoding"), VI_HTTP_ACCEPT_ENCODING, NULL, NULL},
		{ ngx_string("http_accept_language"), VI_HTTP_ACCEPT_LANGUAGE, NULL, NULL},
		{ ngx_string("http_expect"), VI_HTTP_EXPECT, NULL, NULL},
		{ ngx_string("http_cache_control"), VI_HTTP_CACHE_CONTROL, NULL, NULL},
		{ ngx_string("http_connection"), VI_HTTP_CONNECTION, NULL, NULL},
		{ ngx_string("content_length"), VI_HTTP_CONTENT_LENGTH, _trans_atoi, NULL},
		{ ngx_string("content_type"), VI_HTTP_CONTENT_TYPE, NULL, NULL},
		{ ngx_string("remote_user"), VI_HTTP_USER, NULL, NULL},
		{ ngx_string("remote_addr"), VI_IP_SIP, _trans_ip2int, NULL},
		{ ngx_string("remote_port"), VI_TDP_SPORT, _trans_atoi, NULL},
		{ ngx_string("server_addr"), VI_IP_DIP, _trans_ip2int, NULL},
		{ ngx_string("server_port"), VI_TDP_DPORT, _trans_atoi, NULL},
		{ ngx_string("server_protocol"), VI_HTTP_VERSION, NULL, NULL},
		{ ngx_string("request_uri"), VI_HTTP_URL_STR, NULL, NULL}, 
		{ ngx_string("request_method"), VI_HTTP_METHOD, NULL, NULL}, 
		{ ngx_string("query_string"), VI_HTTP_URL_QUERY, NULL, NULL},
		{ ngx_string("decoded_uri"), VI_HTTP_URL, NULL, NULL},
		{ ngx_string("decoded_cookie"),VI_HTTP_COOKIE, NULL, NULL},
		{ ngx_string("decoded_user_agent"),VI_HTTP_USER_AGENT, NULL, NULL}, //overwrite http_user_agent above
//		{ ngx_string("decoded_referer"),VI_HTTP_REFERENCE, NULL, NULL},
//		{ ngx_string("decoded_x_forwarded_for"),VI_HTTP_FORWARDEDFOR, NULL, NULL},

//		{ ngx_string("host"), VI_HTTP_HOST, NULL, NULL},
//		{ ngx_string("request_filename"), VI_HTTP_FILE, NULL, NULL}, 
//		{ ngx_string("status"), VI_HTTP_RETCODE, NULL, NULL},
//		{ ngx_string("uri"), VI_HTTP_URL, NULL, NULL},
//		{ ngx_string("request_length"), VI_HTTP_MSGBODY_LEN, _trans_atoi},
	};

	if (sign_check_init_done == 0) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log, 0, 
					  "[[SIGN]]==> sign_check_init undone, skip check");
		return NGX_DECLINED;
	}

	if (r->skip_sign_check == 1) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "skip sign check according to var set!\n");
		return NGX_DECLINED;
	}

	lcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	/* fix bug2452: response method = forward to server, skip sign check  */
	if (clcf->block_method == NGX_HTTP_BLOCK_METHOD_NONE) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "skip sign check, forwarding!\n");
		return NGX_DECLINED;
	}

	if (lcf->enable) {
		/* read body; this action may cause some delay*/
		if ((r->method == NGX_HTTP_PUT || r->method == NGX_HTTP_POST)
			&& lcf->check_body_size > 0 && r->headers_in.content_length_n > 0) {
			rc = ngx_http_read_client_request_body(r, ngx_http_sign_body_handler);
			if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, 
							  "[[SIGN]]==> rc=%i, hit on request body", rc);
				return rc;
			}
		} else {
			rc = ngx_http_sign_check(r, names, ARRAY_SIZE(names));
			if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
				ngx_log_error(NGX_LOG_INFO,r->connection->log, 0, 
							  "[[SIGN]]==> rc=%i, hit on headers",rc);
				return rc;
			}
		}

	}

	return NGX_DECLINED;
}

#define MAX_SIGN_RULE_CONF_FILES 8
#define SIGN_RULE_FSTAT_DAT "/run/.fstat.dat" 
static ngx_int_t
ngx_http_sign_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt			*h;
	ngx_http_core_main_conf_t 	*cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}
#if (NGX_HAVE_CWAF)
	*h = ngx_http_sign_handler;
#endif


	/* set sign check global conf */
	sign_check_set_conf(SIGN_CONF_SET_ERRLOG_PATH, "/var/log/cwaf/nginx/sign_log");
	sign_check_set_conf(SIGN_CONF_SET_BLOCK_TYPE, SIGN_CONF_BLOCK_TYPE_FORWARD); /* default */

	return NGX_OK;
}

static ngx_int_t
ngx_http_sign_init_module(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_CWAF)
	char *rfiles[MAX_SIGN_RULE_CONF_FILES] = {
		"/usr/local/cwaf/conf/sign/predef_sign_rule.conf",
		NULL,
	};
	ngx_core_conf_t *ccf;
	ngx_uint_t		max_file,max_size,i,n,rfiles_changed,first_time_flag;
	struct stat		old_fstats[MAX_SIGN_RULE_CONF_FILES];
	struct stat		fstats[MAX_SIGN_RULE_CONF_FILES];
	int 			fd = -1;
	char 			*file;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP,cycle->log, 0, 
				  "[[SIGN]]==> in %s process",ngx_process == NGX_PROCESS_MASTER \
				  ? "master" : (ngx_process == NGX_PROCESS_WORKER ? "worker" :"other"));

	/* If nginx used for mngt-web forwarding, return from here  */
	ccf = (ngx_core_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_core_module);
	if (ccf->mngt_web == NGX_MNGT_WEB_ON) {
		ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
					  "[[SIGN]]==> this nginx is used for mngt-web");
		return NGX_OK;
	}

	/* Is anything changed from last time read rfiles */
	max_file = MAX_SIGN_RULE_CONF_FILES;
	max_size = max_file * sizeof(struct stat);
	rfiles_changed = 0;
	first_time_flag = 0;
	memset(&fstats, 0, max_size);
	memset(&old_fstats, 0, max_size);

	if (0 > (fd = open(SIGN_RULE_FSTAT_DAT, O_CREAT|O_EXCL|O_WRONLY, S_IWUSR|S_IRUSR))) {
		if (errno == EEXIST) {
			fd = open(SIGN_RULE_FSTAT_DAT, O_RDWR);
			if (fd < 0) {
				ngx_log_error(NGX_LOG_ERR,cycle->log, 0, 
							  "[[SIGN]]==> open .sign_rule_fstat.dat error!");
				return NGX_ERROR;
			}
		} else {
			ngx_log_error(NGX_LOG_ERR ,cycle->log, 
						  errno, "[[SIGN]]==> creat %s failed", SIGN_RULE_FSTAT_DAT);
			return NGX_ERROR;
		}

		if (0 > read(fd, (void *)&old_fstats, max_size)) {
			ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[[SIGN]]==> read error");
			close(fd);
			return NGX_ERROR;
		}

		for (i=0; NULL!=(file=rfiles[i]); i++) {
			stat(file, &fstats[i]);
		}

		for (i=0; fstats[i].st_mtime && old_fstats[i].st_mtime; i++) {
			ngx_log_debug8(NGX_LOG_DEBUG_HTTP,cycle->log, 
						  0, "[[SIGN]]==> fstats[%i]:{ino=%d, size=%d, mtime=%d} \n "
						  "old_fstats[%i]:{ino=%d, size=%d, mtime=%d}",
						  i, (int)fstats[i].st_ino, (int)fstats[i].st_size, (int)fstats[i].st_mtime,
						  i, (int)old_fstats[i].st_ino, (int)old_fstats[i].st_size, (int)old_fstats[i].st_mtime);

			if ( fstats[i].st_mtime != old_fstats[i].st_mtime
				|| fstats[i].st_size != old_fstats[i].st_size) {
				rfiles_changed = 1;
				lseek(fd, 0, SEEK_SET);
				n = write(fd, &fstats, max_size);
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP,cycle->log, 0, 
							  "[[SIGN]]==> file %i changed, write %i to attr dat file",i,n);
				break;
			}
		}
	} else {
		first_time_flag = 1;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP,cycle->log, 0, "[[SIGN]]==> first time to create,fd=%d",fd);
		for (i=0; NULL!=(file=rfiles[i]); i++) {
			stat(file, &fstats[i]);
			ngx_log_debug4(NGX_LOG_DEBUG_HTTP,cycle->log, 0, 
						  "[[SIGN]]==> fstats[%i]:{ino=%d,size=%z,mtime=%d}", i, 
						  (int)fstats[i].st_ino, fstats[i].st_size, (int)fstats[i].st_mtime);
		}
		n = write(fd, &fstats, max_size);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP,cycle->log, 0, "[[SIGN]]==> write %i", n);
	}
	if (fd >= 0){
		close(fd);
	}

	/* init sign check matchtree structure */
	if (rfiles_changed || first_time_flag/*  || (toggle switch)  */) {
		/* reinit sign check */
		ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "[[SIGN]]==> init sign check");
		if (0 == sign_check_init(rfiles,1)) {
			sign_check_init_done = 1;
		}
	}
#endif
	return NGX_OK;
}

static void
ngx_http_sign_exit_master(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_CWAF)
	/* when receive -s stop or -s quit, remove .fstats.dat file after reap 
	 * all worker */
	(void)remove(SIGN_RULE_FSTAT_DAT);
#endif
}

static ngx_int_t
ngx_http_sign_init_process(ngx_cycle_t *cycle)
{
	/*  
	pin("in %s process\n",ngx_process == NGX_PROCESS_MASTER \
		? "master" : (ngx_process == NGX_PROCESS_WORKER ? "worker" :"other"));
	*/
	return 0;
}

static void
ngx_http_sign_exit_process(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_CWAF)
	if (sign_check_init_done)
		sign_check_clean();
#endif
}
