/*
// ngx_http_mruby_async.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_async.h"
#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_request.h"

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby/array.h>
#include <mruby/opcode.h>
#include <mruby/proc.h>

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_http_request_t *r;
} ngx_mrb_reentrant_t;

static void replace_stop(mrb_irep *irep)
{
  // A part of them refer to https://github.com/h2o/h2o
  // Replace OP_STOP with OP_RETURN to avoid stop VM
  irep->iseq[irep->ilen - 1] = MKOP_AB(OP_RETURN, irep->nlocals, OP_R_NORMAL);
}

void ngx_mrb_run_without_stop(mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  mrb_value mrb_result;

  replace_stop(rproc->body.irep);

  mrb_result = mrb_run(mrb, rproc, mrb_top_self(mrb));
  if (result != NULL) {
    *result = mrb_result;
  }
}

mrb_value ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  mrb_value proc;
  mrb_value *fiber;

  replace_stop(rproc->body.irep);
  proc = mrb_obj_value(mrb_proc_new(mrb, rproc->body.irep));

  fiber = (mrb_value *)ngx_palloc(r->pool, sizeof(mrb_value));
  mrb_value fiber_class = mrb_obj_value(mrb_class_get(mrb, "Fiber"));
  *fiber = mrb_funcall_with_block(mrb, fiber_class, mrb_intern_cstr(mrb, "new"), 0, NULL, proc);

  return ngx_mrb_run_fiber(mrb, fiber, result);
}

mrb_value ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber, mrb_value *result)
{
  mrb_value resume_results = mrb_nil_value();
  mrb_value is_alive = mrb_false_value();

  mrb->ud = fiber;

  // TODO support passing arguments.
  resume_results = mrb_fiber_resume(mrb, *fiber, 0, NULL);

  is_alive = mrb_funcall(mrb, *fiber, "is_alive?", 0, NULL);
  if (result != NULL) {
    *result = resume_results;
  }

  if (mrb_test(is_alive)) {
    mrb_gc_register(mrb, *fiber);
  } else {
    mrb_gc_unregister(mrb, *fiber);
  }

  return is_alive;
}

static void ngx_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_mruby_ctx_t *ctx;
  ngx_int_t rc = NGX_OK;

  re = ev->data;

  if (re->fiber != NULL) {
    ngx_mrb_push_request(re->r);
    if (!mrb_test(ngx_mrb_run_fiber(re->mrb, re->fiber, NULL))) {
      re->fiber = NULL;
    }
    if (re->mrb->exc) {
      ngx_mrb_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), re->r);
      rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  }

  ctx = ngx_http_get_module_ctx(re->r, ngx_http_mruby_module);
  if (ctx != NULL) {
    if (rc != NGX_OK) {
      re->r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = ngx_mrb_finalize_rputs(re->r, ctx);
  } else {
    rc = NGX_ERROR;
  }

  // progress to a next handler or finalize
  if (rc == NGX_OK) {
    re->r->phase_handler++;
    ngx_http_core_run_phases(re->r);
  } else {
    ngx_http_finalize_request(re->r, rc);
  }
}

static mrb_value ngx_mrb_async_sleep(mrb_state *mrb, mrb_value self)
{
  unsigned int timer;
  u_char *p;
  ngx_event_t *ev;
  ngx_mrb_reentrant_t *re;
  ngx_http_request_t *r;

  mrb_get_args(mrb, "i", &timer);

  mrb_fiber_yield(mrb, 0, NULL);

  r = ngx_mrb_get_request();

  p = ngx_palloc(r->pool, sizeof(ngx_event_t) + sizeof(ngx_mrb_reentrant_t));

  re = (ngx_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;
  re->fiber = (mrb_value *)mrb->ud;
  re->r = r;

  ev = (ngx_event_t *)p;
  ngx_memzero(ev, sizeof(ngx_event_t));
  ev->handler = ngx_mrb_timer_handler;
  ev->data = re;
  ev->log = ngx_cycle->log;

  ngx_add_timer(ev, (ngx_msec_t)timer);

  return self;
}

void ngx_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_async;

  class_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_async, "sleep", ngx_mrb_async_sleep, MRB_ARGS_REQ(1));
}
