#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_request_headers_detector(ngx_http_request_t *r);
ngx_int_t ngx_http_request_body_detector(ngx_http_request_t *r, ngx_chain_t *in);