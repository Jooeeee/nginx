#include "test_print.h"
//for test------------------------------------------

char test_print_ngx_list(ngx_list_t header)
{
    ngx_list_part_t *part = &header.part;
    ngx_table_elt_t *tb = part->elts;
    ngx_uint_t i = 0;
    char rnt = -1;
    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
            {
                break;
            }
            part = part->next;
            tb = part->elts;
            i = 0;
        }
        if (tb[i].key.len == 7)
            if (tb[i].value.data[0] == 'q')
                rnt = 'z';
            else if (tb[i].value.data[0] == 'a')
                rnt = 'a';
        printf("%*s, %*s\n", (int)tb[i].key.len, tb[i].key.data, (int)tb[i].value.len, tb[i].value.data);
    }
    return rnt;
}

char test_print_chain(ngx_chain_t *bufs)
{
    ngx_int_t cnt = 1;
    char rnt = -1;
    ngx_int_t flag = 1;
    while (bufs != NULL)
    {
        ngx_buf_t *buf = bufs->buf;
        if (ngx_buf_in_memory(buf))
        {
            if (flag)
            {
                flag = 0;
                rnt = (buf->pos)[0];
            }
            printf("body in memory(%d,%p). pos size: %d,%.30s......%.30s\n", cnt++, buf->start, ngx_buf_size(buf), buf->pos, buf->last - 30);
            // printf("%s", buf->pos);
        }
        if (!ngx_buf_in_memory_only(buf))
        {
            if (flag)
            {
                flag = 0;
                rnt = buf->pos;
            }
            printf("body in file(%d):pos size: %d,  %.10s\n", cnt++, ngx_buf_size(buf), buf->file_pos);
        }
        bufs = bufs->next;
    }
    return rnt;
}

ngx_int_t test_print_request_headers(ngx_list_t header)
{
    printf("---------------Request headers start-------------\n");
    char rnt = test_print_ngx_list(header);
    printf("---------------Request headers end-------------\n");
    if (rnt == 'q')
    {
        return NGX_HTTP_SPECIAL_RESPONSE;
    }
    return NGX_OK;
}

ngx_int_t test_print_request_body(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (in == NULL)
    {
        printf("---------------NO Request Body-------------------\n");
        return NGX_OK;
    }

    printf("---------------Request Body start-------------------\n");
    char rnt = test_print_chain(in);

    if (r->request_body && r->request_body->last)
    {
        printf("---------------last package-------------------\n");
        test_print_chain(r->request_body->last);
    }

    printf("---------------Request Body end---------------------\n");
    if (rnt == 'z')
    {
        return NGX_HTTP_SPECIAL_RESPONSE;
    }

    return NGX_OK;
}

ngx_int_t test_print_request(ngx_http_request_t *r)
{
    test_print_request_headers(r->headers_in.headers);
    if ((r->method == NGX_HTTP_PUT || r->method == NGX_HTTP_POST) && r->headers_in.content_length_n > 0 && r->request_body && r->request_body->last)
    {
        test_print_chain(r->request_body->bufs);
    }
    return NGX_OK;
}

char test_print_response_headers(ngx_http_request_t *r)
{
    printf("---------------headers_out-------------\n");
    char rnt = test_print_ngx_list(r->headers_out.headers);
    printf("---------------upstream.headers_in-------------\n");
    if (r->upstream != NULL)
        rnt = test_print_ngx_list(r->upstream->headers_in.headers);
    return rnt;
}

char test_print_response_body(ngx_chain_t *bufs)
{
    if (bufs == NULL)
    {
        printf("---------------NO Response Body-------------------\n");
        return NGX_OK;
    }
    printf("---------------Response Body start-------------------\n");
    char rnt = test_print_chain(bufs);
    printf("---------------Response Body end---------------------\n");

    return rnt;
}

// ngx_int_t test_get_and_print_response(ngx_http_request_t *r, ngx_chain_t *bufs)
// {
//     char rnt = test_print_response_headers(r);
//     if (rnt == 'z')
//     {
//         return NGX_HTTP_SPECIAL_RESPONSE;
//     }
//     rnt = test_print_response_body(bufs);
//     if (rnt == 'z')
//     {
//         return NGX_HTTP_SPECIAL_RESPONSE;
//     }
//     return NGX_OK;
// }

//------------------------------------------------