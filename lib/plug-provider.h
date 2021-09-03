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

#ifndef PLUG_PROVIDER_H
#define PLUG_PROVIDER_H 1

/* Provider interface to pluggers.  A plugger implementation performs lookup
 * and/or initialization of ports, typically representor ports, using generic
 * non-blocking hardware interfaces.  This allows the ovn-controller to, upon
 * the CMS's request, create ports and interfaces in the chassis's Open vSwitch
 * instances (also known as vif plugging).
 */

#include <stdbool.h>

#include "plug.h"

#ifdef __cplusplus
extern "C" {
#endif

struct plug_class {
    /* Type of plugger in this class. */
    const char *type;

    /* Called when the plug provider is registered, typically at program
     * startup.
     *
     * This function may be set to null if a plug class needs no
     * initialization at registration time. */
    int (*init)(void);

    /* Called when the plug provider is unregistered, typically at program
     * exit.
     *
     * This function may be set to null if a plug class needs no
     * de-initialization at unregister time.*/
    int (*destroy)(void);

    /* Performs periodic work needed by plugger, if any is necessary.  Returns
     * 'true; if the changes encountered could be handled incrementally,
     * 'false' otherwise.
     *
     * Note that returning 'false' will instruct the incremental processing
     * engine to perform a full recomputation. */
    bool (*run)(struct plug_class *);

    /* Retrieve Interface options this plugger will maintain.  This set is used
     * to know which items to remove when maintaining the database record. */
    const struct sset * (*plug_get_maintained_iface_options)(void);

    /* Pass plug_port_ctx_in to plug implementation to prepare for port
     * creation/update.
     *
     * The plug implemantation can perform lookup or any per port
     * initialization and should fill plug_port_ctx_out with data required for
     * port/interface creation.  The plug implementation should return true if
     * it wants the caller to create/update a port/interface, false otherwise.
     *
     * Data in the plug_port_ctx_out struct is owned by the plugging library,
     * and a call must be made to the plug_port_ctx_destroy callback to free
     * up any allocations when done with port creation/update.
     */
    bool (*plug_port_prepare)(const struct plug_port_ctx_in *,
                              struct plug_port_ctx_out *);

    /* Notify plugging library that port update is done. */
    void (*plug_port_finish)(const struct plug_port_ctx_in *,
                             struct plug_port_ctx_out *);

    /* Free any allocations made by the plug_port_prepare callback. */
    void (*plug_port_ctx_destroy)(const struct plug_port_ctx_in *,
                                  struct plug_port_ctx_out *);
};

extern const struct plug_class plug_dummy_class;
#ifdef ENABLE_PLUG
/* in-tree plug classes */
extern const struct plug_class plug_representor;
#endif /* ENABLE_PLUG */
#ifdef HAVE_PLUG_PROVIDER
extern const struct plug_class *plug_provider_classes[];
#endif /* HAVE_PLUG_PROVIDER */

#ifdef  __cplusplus
}
#endif

#endif /* plug-provider.h */
