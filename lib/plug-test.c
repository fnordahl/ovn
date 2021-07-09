/*
 * Copyright (c) 2021 Canonical
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "plug-provider.h"
#include "plug.h"

#include <stdint.h>

#include "ovsport.h"
#include "openvswitch/vlog.h"
#include "smap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(plug_test);

struct plug_test {
    struct plug plug;
};

static struct sset plug_test_maintained_iface_options;

static int
plug_test_init(void)
{
    sset_init(&plug_test_maintained_iface_options);
    sset_add(&plug_test_maintained_iface_options, "dpdk-devargs");

    return 0;
}

static int
plug_test_destroy(void)
{
    sset_destroy(&plug_test_maintained_iface_options);

    return 0;
}

static int
plug_test_open(const struct plug_class *class, struct plug **plugp)
{
    struct plug_test *plug;

    plug = xmalloc(sizeof *plug);
    plug->plug.plug_class = class;
    *plugp = &plug->plug;

    VLOG_INFO("plug_test_open(%p)", plug);
    return 0;
}

static int
plug_test_close(struct plug *plug)
{
    VLOG_INFO("plug_test_close(%p)", plug);
    free(plug);

    return 0;
}

static bool
plug_test_run(struct plug *plug)
{
    VLOG_INFO("plug_test_run(%p)", plug);

    return false;
}

static bool
plug_test_port_prepare(const struct plug_port_ctx_in *ctx_in,
                       struct plug_port_ctx_out *ctx_out)
{
    VLOG_INFO("plug_test_port_prepare: %s", ctx_in->lport_name);
    if (ctx_in->op_type == PLUG_OP_CREATE)
    {
        ctx_out->name = strdup("test");
        ctx_out->type = strdup("internal");
        ctx_out->iface_options = xmalloc(sizeof *ctx_out->iface_options);
        smap_init(ctx_out->iface_options);
    }

    return true;
}

static void
plug_test_port_finish(const struct plug_port_ctx_in *ctx_in,
                      struct plug_port_ctx_out *ctx_out OVS_UNUSED)
{
    VLOG_INFO("plug_test_port_finish: %s", ctx_in->lport_name);
}

static void
plug_test_port_ctx_destroy(const struct plug_port_ctx_in *ctx_in,
                           struct plug_port_ctx_out *ctx_out)
{
    VLOG_INFO("plug_test_port_ctx_destroy: %s", ctx_in->lport_name);
    ovs_assert(ctx_in->op_type == PLUG_OP_CREATE);
    free(ctx_out->name);
    free(ctx_out->type);
    smap_destroy(ctx_out->iface_options);
    free(ctx_out->iface_options);
}

const struct plug_class plug_test_class = {
    .type = "test",
    .maintained_iface_options = &plug_test_maintained_iface_options,
    .init = plug_test_init,
    .destroy = plug_test_destroy,
    .open = plug_test_open,
    .close = plug_test_close,
    .run = plug_test_run,
    .plug_port_prepare = plug_test_port_prepare,
    .plug_port_finish = plug_test_port_finish,
    .plug_port_ctx_destroy = plug_test_port_ctx_destroy,
};
