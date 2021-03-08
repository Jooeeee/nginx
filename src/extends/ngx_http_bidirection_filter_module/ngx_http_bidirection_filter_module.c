#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "test_print.h"

typedef struct
{
    ngx_int_t bidirection_switch;
} ngx_http_bidirection_loc_conf_t;

static ngx_int_t ngx_http_bidirection_filter_init(ngx_conf_t *cf);
// static ngx_int_t ngx_http_bidirection_filter(ngx_http_request_t *r);
static void *ngx_http_bidirection_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_bidirection_filter_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_command_t ngx_http_bidirection_filter_commands[] = {
    {ngx_string("bidirection_netflow_detect"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_http_bidirection_filter_set,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_bidirection_loc_conf_t, bidirection_switch),
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_bidirection_module_ctx = {
    NULL, ngx_http_bidirection_filter_init, NULL, NULL, NULL, NULL, ngx_http_bidirection_create_loc_conf, NULL};

ngx_module_t ngx_http_bidirection_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_bidirection_module_ctx,
    ngx_http_bidirection_filter_commands,
    NGX_HTTP_MODULE,
    NGX_HTTP_MODULE, /* module type */
    NULL,            /* init master */
    NULL,            /* init module */
    NULL,            /* init process */
    NULL,            /* init thread */
    NULL,            /* exit thread */
    NULL,            /* exit process */
    NULL,            /* exit master */
    NGX_MODULE_V1_PADDING};

static void *ngx_http_bidirection_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_bidirection_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_bidirection_loc_conf_t));
    if (local_conf == NULL)
    {
        return NULL;
    }
    local_conf->bidirection_switch = NGX_CONF_UNSET;
    return local_conf;
}

static char *ngx_http_bidirection_filter_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_bidirection_loc_conf_t *local_conf;
    local_conf = conf;
    char *rv = NULL;
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Bidirection Netflow Detection: %d", local_conf->bidirection_switch);
    return rv;
}

static ngx_int_t ngx_http_bidirection_header_filter(ngx_http_request_t *r)
{
    char rnt;
    rnt = test_print_response_headers(r);
    if (rnt == 'a')
    {
        // ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        //               "Bidirection Netflow Detection hit: %d", rc);

        printf("### Return NGX_HTTP_SPECIAL_RESPONSE ###\n");
        // ngx_http_upstream_next(r, r->upstream, NGX_HTTP_UPSTREAM_FT_ERROR);
        return NGX_ERROR;
    }
    return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_bidirection_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    char rc = test_print_response_body(in);
    // test_print_response_body(r->out);
    if (rc == 'z')
    {
        //     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        //                   "Bidirection Netflow Detection hit: %d", rc);
        printf("### Return NGX_HTTP_SPECIAL_RESPONSE ###\n");
        // ngx_http_upstream_next(r, r->upstream, NGX_HTTP_UPSTREAM_FT_ERROR);
        in->buf->last = in->buf->pos;
        in->next = NULL;
        return NGX_ERROR;
    }
    return ngx_http_next_body_filter(r, in);
}
static ngx_int_t ngx_http_bidirection_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_bidirection_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_bidirection_body_filter;

    return NGX_OK;
}