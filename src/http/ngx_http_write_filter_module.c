
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_write_filter_module_ctx = {
    NULL,                       /* preconfiguration */
    ngx_http_write_filter_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL, /* merge location configuration */
};

ngx_module_t ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx, /* module context */
    NULL,                              /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING};

// 将要发送的内容连接到r->out上；
// 发送的内容再r->out；
// 根据flush、recycled、last等标记位决定是否立即调用发送逻辑；
// 根据postpone_output确定是否推迟发送；
// 根据发送是否完成，返回NGX_OK或NGX_AGAIN
// 
ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t size, sent, nsent, limit;
    ngx_uint_t last, flush, sync;
    ngx_msec_t delay;
    ngx_chain_t *cl, *ln, **ll, *chain;
    ngx_connection_t *c;
    ngx_http_core_loc_conf_t *clcf;

    c = r->connection;

    if (c->error)
    {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */
    // 计算之前没有发送完成的内容大小并检查是否存在特殊标志。
    // 为了优化性能，当没有必要立即发送响应且响应内容大小没有达到设置的阀值时，
    // NGINX可以暂时推迟发送该部分响应。参看:postpone_output指令。
    // flush标志表示需要立即发送响应。
    // recycled表示该buffer需要循环使用，因而需要立即发送以释放该buffer被重新使用。
    // last标志表示该buffer是响应的最后一部分内容，因而也需要立即发送。
    for (cl = r->out; cl; cl = cl->next)
    {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf))
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }

        if (ngx_buf_size(cl->buf) < 0)
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled)
        {
            flush = 1;
        }

        if (cl->buf->sync)
        {
            sync = 1;
        }

        if (cl->buf->last_buf)
        {
            last = 1;
        }
    }

    /* add the new chain to the existent one */
    //计算本次将发送的内容大小，检查是否存在特殊标志，并将内容链接到r->out上。
    for (ln = in; ln; ln = ln->next)
    {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL)
        {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf))
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }

        if (ngx_buf_size(cl->buf) < 0)
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled)
        {
            flush = 1;
        }

        if (cl->buf->sync)
        {
            sync = 1;
        }

        if (cl->buf->last_buf)
        {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */
    // 根据情况决定是需要真正进行网络I/O操作, 还是直接返回。
    if (!last && !flush && in && size < (off_t)clcf->postpone_output)
    {
        return NGX_OK;
    }

    if (c->write->delayed)
    {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0 && !(c->buffered & NGX_LOWLEVEL_BUFFERED) && !(last && c->need_last_buf))
    {
        if (last || flush || sync)
        {
            for (cl = r->out; cl; /* void */)
            {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    if (!r->limit_rate_set)
    {
        r->limit_rate = ngx_http_complex_value_size(r, clcf->limit_rate, 0);
        r->limit_rate_set = 1;
    }

    if (r->limit_rate)
    {

        if (!r->limit_rate_after_set)
        {
            r->limit_rate_after = ngx_http_complex_value_size(r,
                                                              clcf->limit_rate_after, 0);
            r->limit_rate_after_set = 1;
        }

        limit = (off_t)r->limit_rate * (ngx_time() - r->start_sec + 1) - (c->sent - r->limit_rate_after);

        if (limit <= 0)
        {
            c->write->delayed = 1;
            delay = (ngx_msec_t)(-limit * 1000 / r->limit_rate + 1);
            ngx_add_timer(c->write, delay);

            c->buffered |= NGX_HTTP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

        if (clcf->sendfile_max_chunk && (off_t)clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }
    }
    else
    {
        limit = clcf->sendfile_max_chunk;
    }

    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR)
    {
        c->error = 1;
        return NGX_ERROR;
    }

    if (r->limit_rate)
    {

        nsent = c->sent;

        if (r->limit_rate_after)
        {

            sent -= r->limit_rate_after;
            if (sent < 0)
            {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0)
            {
                nsent = 0;
            }
        }

        delay = (ngx_msec_t)((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0)
        {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    if (limit && c->write->ready && c->sent - sent >= limit - (off_t)(2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    // 回收发送完成内容的buffer和chain结构, 将没有发送完成的内容存入r->out
    for (cl = r->out; cl && cl != chain; /* void */)
    {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    r->out = chain;
    //根据发送是否完成，返回NGX_OK或NGX_AGAIN
    if (chain)
    {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL)
    {
        return NGX_AGAIN;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
