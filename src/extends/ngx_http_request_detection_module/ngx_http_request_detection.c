#include "ngx_http_request_detection.h"

ngx_chain_t *
ngx_chain_copy_chains(ngx_pool_t *pool, ngx_chain_t **free, ngx_chain_t *in)
{
    ngx_chain_t *cl, *ll, *head;
    head = cl = ll = NULL;
    ngx_buf_t *b, *inb;
    while (in)
    {
        cl = ngx_chain_get_free_buf(pool, free);
        if (cl == NULL)
        {
            return NULL;
        }

        b = cl->buf;
        inb = in->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));
        b->temporary = 1;
        b->tag = inb->tag;
        b->start = inb->pos;
        b->pos = inb->pos;
        b->last = inb->last;
        b->end = inb->end;
        b->flush = inb->flush;

        if (ll == NULL)
        {
            head = cl;
        }
        else
        {
            ll->next = cl;
        }
        ll = cl;
        in = in->next;
    }

    return head;
}

ngx_int_t ngx_http_request_headers_detector(ngx_http_request_t *r)
{
    return test_print_request_headers(r->headers_in.headers);
}

ngx_int_t ngx_http_request_body_detector(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t rc;
    ngx_chain_t *ln;
    rc = test_print_request_body(r, in);
    if (r->request_body)
    {
        ngx_http_request_body_t *rb;
        rb = r->request_body;
        while (rb->last)
        {
            ln = rb->last;
            rb->last = rb->last->next;
            ngx_free_chain(r->pool, ln);
        }
        rb->last = ngx_chain_copy_chains(r->pool, &rb->free, in);
    }
    return rc;
}