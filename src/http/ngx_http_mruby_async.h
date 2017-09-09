/*
// ngx_http_mruby_async.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_ASYNC_H
#define NGX_HTTP_MRUBY_ASYNC_H

#include <mruby.h>

void ngx_mrb_prepare_fiber(mrb_state *mrb, struct RProc* proc, mrb_value *fiber);
mrb_value ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber, mrb_value *result);

#endif // NGX_HTTP_MRUBY_ASYNC_H
