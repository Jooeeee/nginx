#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

char test_print_response_headers(ngx_http_request_t *r);
char test_print_response_body(ngx_chain_t *bufs);
ngx_int_t test_print_request(ngx_http_request_t *r);
ngx_int_t test_get_and_print_request(ngx_http_request_t *r);
ngx_int_t test_get_and_print_response(ngx_http_request_t *r, ngx_chain_t *bufs);

ngx_int_t ngx_http_request_headers_detector(ngx_http_request_t *r);
ngx_int_t ngx_http_request_body_detector(ngx_http_request_t *r, ngx_chain_t *in);