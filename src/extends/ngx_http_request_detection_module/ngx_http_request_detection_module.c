#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_request_detection.h"

typedef struct
{
    ngx_flag_t request_detection_headers;
    ngx_flag_t request_detection_body;
} ngx_http_request_detection_loc_conf_t;

static ngx_int_t ngx_http_request_detection_init(ngx_conf_t *cf);

static void *ngx_http_request_detection_create_loc_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_request_detection_commands[] = {
    {ngx_string("request_detection_headers"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_request_detection_loc_conf_t, request_detection_headers),
     NULL},

    {ngx_string("request_detection_body"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_request_detection_loc_conf_t, request_detection_body),
     NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_request_detection_module_ctx = {
    NULL,                            /* preconfiguration */
    ngx_http_request_detection_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_request_detection_create_loc_conf, /* create location configuration */
    NULL                                        /* merge location configuration */
};

ngx_module_t ngx_http_request_detection_module = {
    NGX_MODULE_V1,
    &ngx_http_request_detection_module_ctx, /* module context */
    ngx_http_request_detection_commands,    /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_request_detection_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_http_request_detection_loc_conf_t *my_conf;
    u_char ngx_request_detection_string[1024] = {0};
    ngx_uint_t content_length = 0;

    my_conf = ngx_http_get_module_loc_conf(r, ngx_http_request_detection_module);
    if (my_conf->request_detection_headers)
    {
        rc = ngx_http_request_headers_detector(r);
        if (rc != NGX_OK)
        {
            return rc;
        }
    }
    // move body detection into upstream module
    // if (my_conf->request_detection_body)
    // {
    //     rc = ngx_http_request_body_detector(r);
    //     if (rc != NGX_OK)
    //     {
    //         return rc;
    //     }
    // }

    return NGX_OK;
}

static void *ngx_http_request_detection_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_request_detection_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_request_detection_loc_conf_t));
    if (local_conf == NULL)
    {
        return NULL;
    }

    local_conf->request_detection_headers = NGX_CONF_UNSET;
    local_conf->request_detection_body = NGX_CONF_UNSET;

    return local_conf;
}

static char *ngx_http_request_detection_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_request_detection_loc_conf_t *prev = parent;
    ngx_http_request_detection_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->request_detection_headers,
                         prev->request_detection_headers, 1);
    ngx_conf_merge_value(conf->request_detection_body,
                         prev->request_detection_body, 1);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_request_detection_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_request_detection_handler;

    return NGX_OK;
}