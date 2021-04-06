/* Copyright (c) 2021 Canonical
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
#include <errno.h>
#include <inttypes.h>
#include <linux/devlink.h>
#include <net/if.h>

#include "plugging.h"

#include "hash.h"
#include "lflow.h"
#include "lib/vswitch-idl.h"
#include "lport.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "lib/ovn-sb-idl.h"
#include "netlink-devlink.h"
#include "ovn-controller.h"
#include "openvswitch/shash.h"
#include "packets.h"

VLOG_DEFINE_THIS_MODULE(plugging);

/* Contains netdev name of ports known to devlink indexed by PF MAC
 * address and logical function number (if applicable).
 *
 * Examples:
 *     SR-IOV Physical Function: key "00:53:00:00:00:42"    value "pf0hpf"
 *     SR-IOV Virtual Function:  key "00:53:00:00:00:42-42" value "pf0vf42"
 */
static struct shash devlink_ports;

/* Max number of physical ports connected to a single NIC SoC. */
#define MAX_NIC_PHY_PORTS 64
/* string repr of eth MAC, '-', logical function number (uint32_t) */
#define MAX_KEY_LEN 17+1+10+1


static bool compat_get_host_pf_mac(const char *, struct eth_addr *);

static bool
fill_devlink_ports_key_from_strs(char *buf, size_t bufsiz,
                                const char *host_pf_mac,
                                const char *function)
{
    return snprintf(buf, bufsiz,
                    function != NULL ? "%s-%s": "%s",
                    host_pf_mac, function) < bufsiz;
}

/* We deliberately pass the struct eth_addr by value as we would have to copy
 * the data either way to make use of the ETH_ADDR_ARGS macro */
static bool
fill_devlink_ports_key_from_typed(char *buf, size_t bufsiz,
                    struct eth_addr host_pf_mac,
                    uint32_t function)
{
    return snprintf(
        buf, bufsiz,
        function < UINT32_MAX ? ETH_ADDR_FMT"-%"PRIu32 : ETH_ADDR_FMT,
        ETH_ADDR_ARGS(host_pf_mac), function) < bufsiz;
}

static void
devlink_port_add_function(struct dl_port *port_entry,
                          struct eth_addr *host_pf_mac)
{
    char keybuf[MAX_KEY_LEN];
    uint32_t function_number;

    switch(port_entry->flavour) {
    case DEVLINK_PORT_FLAVOUR_PCI_PF:
        /* for Physical Function representor ports we only add the MAC address
         * and no logical function number */
        function_number = -1;
        break;
    case DEVLINK_PORT_FLAVOUR_PCI_VF:
        function_number = port_entry->pci_vf_number;
        break;
    default:
        VLOG_WARN("Unsupported flavour for port '%s': %s",
            port_entry->netdev_name,
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_PHYSICAL ? "PHYSICAL" :
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_CPU ? "CPU" :
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_DSA ? "DSA" :
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_PCI_PF ? "PCI_PF":
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_PCI_VF ? "PCI_VF":
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_VIRTUAL ? "VIRTUAL":
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_UNUSED ? "UNUSED":
            port_entry->flavour == DEVLINK_PORT_FLAVOUR_PCI_SF ? "PCI_SF":
            "UNKNOWN");
        return;
    };
    /* Failure to fill key from typed values means calculation of the max key
     * length is wrong, i.e. a bug. */
    ovs_assert(fill_devlink_ports_key_from_typed(
                            keybuf, sizeof(keybuf),
                            *host_pf_mac, function_number));
    shash_add(&devlink_ports, keybuf, xstrdup(port_entry->netdev_name));
}


void
plugging_init(void)
{
    struct nl_dl_dump_state *port_dump;
    struct dl_port port_entry;
    int error;
    struct eth_addr host_pf_macs[MAX_NIC_PHY_PORTS];

    shash_init(&devlink_ports);

    port_dump = nl_dl_dump_init();
    if ((error = nl_dl_dump_init_error(port_dump))) {
        VLOG_WARN(
            "unable to start dump of ports from devlink-port interface");
        return;
    }
    /* The core devlink infrastructure in the kernel keeps a linked list of
     * the devices and each of those has a linked list of ports. These are
     * populated by each device driver as devices are enumerated, and as such
     * we can rely on ports being dumped in a consistent order on a device
     * by device basis with logical numbering for each port flavour starting
     * on 0 for each new device.
     */
    nl_dl_dump_start(DEVLINK_CMD_PORT_GET, port_dump);
    while (nl_dl_port_dump_next(port_dump, &port_entry)) {
        switch (port_entry.flavour) {
        case DEVLINK_PORT_FLAVOUR_PHYSICAL:
            /* The PHYSICAL flavoured port represent a network facing port on
             * the NIC.
             *
             * For kernel versions where the devlink-port infrastructure does
             * not provide MAC address for PCI_PF flavoured ports, there exist
             * a interface in sysfs which is relative to the name of the
             * PHYSICAL port netdev name.
             *
             * Since we at this point in the dump do not know if the MAC will
             * be provided for the PCI_PF or not, proactively store the MAC
             * address by looking up through the sysfs interface.
             *
             * If MAC address is available once we get to the PCI_PF we will
             * overwrite the stored value.
             */
            if (port_entry.number > MAX_NIC_PHY_PORTS) {
                VLOG_WARN("physical port number out of range for port '%s': "
                          "%"PRIu32,
                          port_entry.netdev_name, port_entry.number);
                continue;
            }
            compat_get_host_pf_mac(port_entry.netdev_name,
                                   &host_pf_macs[port_entry.number]);
            break;
        case DEVLINK_PORT_FLAVOUR_PCI_PF: /* FALL THROUGH */
            /* The PCI_PF flavoured port represent a host facing port.
             *
             * For function flavours other than PHYSICAL pci_pf_number will be
             * set to the logical number of which physical port the function
             * belongs.
             */
            if (!eth_addr_is_zero(port_entry.function.eth_addr)) {
                host_pf_macs[port_entry.pci_pf_number] =
                    port_entry.function.eth_addr;
            }
            /* FALL THROUGH */
        case DEVLINK_PORT_FLAVOUR_PCI_VF:
            /* The PCI_VF flavoured port represent a host facing
             * PCI Virtual Function.
             *
             * For function flavours other than PHYSICAL pci_pf_number will be
             * set to the logical number of which physical port the function
             * belongs.
             */
            if (port_entry.pci_pf_number > MAX_NIC_PHY_PORTS) {
                VLOG_WARN("physical port number out of range for port '%s': "
                          "%"PRIu32,
                          port_entry.netdev_name, port_entry.pci_pf_number);
                continue;
            }
            devlink_port_add_function(&port_entry,
                                      &host_pf_macs[port_entry.pci_pf_number]);
            break;
        };
    }
    nl_dl_dump_finish(port_dump);
    nl_dl_dump_destroy(port_dump);

    struct shash_node *node;
    SHASH_FOR_EACH (node, &devlink_ports) {
        VLOG_INFO("HELLO %s -> %s", node->name, (char*)node->data);
    }
}

void
plugging_destroy(void)
{
    shash_destroy_free_data(&devlink_ports);
}

static bool
match_port (const struct ovsrec_port *port, const char *name)
{
    return !name || !name[0]
           || !strcmp(port->name, name);
}

/* Creates a port in bridge 'br_int' named 'name'.
 *
 * If such a port already exists, removes it from 'existing_ports'. */
static void
create_port(struct ovsdb_idl_txn *ovs_idl_txn,
                  const char *iface_id,
                  const struct ovsrec_bridge *br_int, const char *name,
                  struct shash *existing_ports)
{
    for (size_t i = 0; i < br_int->n_ports; i++) {
        if (match_port(br_int->ports[i], name)) {
            VLOG_INFO("port already created: %s %s", iface_id, name);
            shash_find_and_delete(existing_ports, br_int->ports[i]->name);
            return;
        }
    }

    ovsdb_idl_txn_add_comment(ovs_idl_txn,
            "ovn-controller: plugging port '%s' into '%s'",
            name, br_int->name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ovs_idl_txn);
    ovsrec_interface_set_name(iface, name);
    const struct smap ids = SMAP_CONST2(
        &ids,
        "iface-id", iface_id,
        "ovn-plugged", "true");
    ovsrec_interface_set_external_ids(iface, &ids);

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ovs_idl_txn);
    ovsrec_port_set_name(port, name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    struct ovsrec_port **ports;
    ports = xmalloc(sizeof *ports * (br_int->n_ports + 1));
    memcpy(ports, br_int->ports, sizeof *ports * br_int->n_ports);
    ports[br_int->n_ports] = port;
    ovsrec_bridge_verify_ports(br_int);
    ovsrec_bridge_set_ports(br_int, ports, br_int->n_ports + 1);

    free(ports);
}

static void
remove_port(const struct ovsrec_bridge *br_int,
            const struct ovsrec_port *port)
{
    for (size_t i = 0; i < br_int->n_ports; i++) {
        if (br_int->ports[i] != port) {
            continue;
        }
        struct ovsrec_port **new_ports;
        new_ports = xmemdup(br_int->ports,
                sizeof *new_ports * (br_int->n_ports - 1));
        if (i != br_int->n_ports - 1) {
            /* Removed port was not last */
            new_ports[i] = br_int->ports[br_int->n_ports - 1];
        }
        ovsrec_bridge_verify_ports(br_int);
        ovsrec_bridge_set_ports(br_int, new_ports, br_int->n_ports - 1);
        free(new_ports);
        ovsrec_port_delete(port);
        return;
    }
}

static bool
can_plug(const char *vif_plugging)
{
    return !vif_plugging || !vif_plugging[0]
           || !strcmp(vif_plugging, "true");
}

void
plugging_run(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct sbrec_port_binding_table *port_binding_table,
             const struct ovsrec_port_table *port_table,
             const struct ovsrec_bridge *br_int,
             const struct sbrec_chassis *chassis)
{
    if (!ovs_idl_txn) {
        return;
    }

    /* Figure out what ports managed by OVN already exist. */
    struct shash existing_ports = SHASH_INITIALIZER(&existing_ports);
    const struct ovsrec_port *port;
    OVSREC_PORT_TABLE_FOR_EACH (port, port_table) {
        for (size_t i = 0; i < port->n_interfaces; i++) {
            struct ovsrec_interface *iface = port->interfaces[i];
            const char *port_iface_id;
            if (can_plug(smap_get(&iface->external_ids, "ovn-plugged"))
                && (port_iface_id = smap_get(&iface->external_ids,
                                             "iface-id"))) {
                shash_add(&existing_ports, port_iface_id, port);
            }
        }
    }

    /* Iterate over currently unbound ports destined for this chassis or ports
     * already bound to this chassis and check if OVN management is requested.
     * Remove ports from 'existing_ports' that do exist in the database and
     * should be there. */
    const struct sbrec_port_binding *port_binding;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (port_binding,
                                       port_binding_table)
    {
        VLOG_INFO("HELLO %s", port_binding->logical_port);
        const char *vif_chassis = smap_get(&port_binding->options,
                                           "requested-chassis");
        const char *vif_plugging = smap_get_def(&port_binding->options,
                                                "ovn-plugging",
                                                "false");
        VLOG_INFO("HELLO %s", port_binding->logical_port);
        if (lport_can_bind_on_this_chassis(chassis, vif_chassis)
            && can_plug(vif_plugging))
        {
            char keybuf[MAX_KEY_LEN];
            const char *rep_port;
            const char *pf_mac;
            const char *vf_num;

            if (!fill_devlink_ports_key_from_strs(
                                    keybuf, sizeof(keybuf),
                                    (pf_mac = smap_get(
                                        &port_binding->options, "pf-mac")),
                                    (vf_num = smap_get(
                                        &port_binding->options, "vf-num"))))
            {
                /* Overflow, most likely incorrect input data from database */
                VLOG_WARN("Southbound DB port plugging options out of range: "
                          "pf-mac: '%s' vf-num: '%s'", pf_mac, vf_num);
                continue;
            }

            shash_find_and_delete(&existing_ports, port_binding->logical_port);

            rep_port = shash_find_data(&devlink_ports, keybuf);
            VLOG_INFO("plug %s (%s) -> %s",
                      port_binding->logical_port, rep_port, br_int->name);
            create_port(ovs_idl_txn, port_binding->logical_port,
                        br_int, rep_port, &existing_ports);
        }
    }

    /* Now 'existing_ports' only contains ports that exist in the
     * database but shouldn't.  Delete them from the database. */
    struct shash_node *port_node, *port_next_node;
    SHASH_FOR_EACH_SAFE (port_node, port_next_node, &existing_ports) {
        port = port_node->data;
        shash_delete(&existing_ports, port_node);
        VLOG_INFO("remove port %s", port->name);
        remove_port(br_int, port);
    }
    shash_destroy(&existing_ports);
}

/* The kernel devlink-port interface provides a vendor neutral and standard way
 * of discovering host visible resources such as MAC address of interfaces from
 * a program running on the NIC SoC side.
 *
 * However a fairly recent kernel version is required for it to work, so until
 * this is widely available we provide this helper to retrieve the same
 * information from the interim sysfs solution. */
static bool
compat_get_host_pf_mac(const char *netdev_name, struct eth_addr *ea)
{
    char file_name[IFNAMSIZ+35+1];
    FILE *stream;
    char line[128];
    bool retval = false;

    snprintf(file_name, sizeof(file_name),
             "/sys/class/net/%s/smart_nic/pf/config", netdev_name);
    stream = fopen(file_name, "r");
    if (!stream) {
        VLOG_WARN("%s: open failed (%s)",
                  file_name, ovs_strerror(errno));
        *ea = eth_addr_zero;
        return false;
    }
    while (fgets(line, sizeof(line), stream)) {
        char key[16];
        char *cp;
        if (ovs_scan(line, "%15[^:]: ", key)
            && key[0] == 'M' && key[1] == 'A' && key[2] == 'C')
        {
            /* strip any newline character */
            if ((cp = strchr(line, '\n')) != NULL) {
                *cp = '\0';
            }
            /* point cp at end of key + ': ', i.e. start of MAC address */
            cp = line + strnlen(key, sizeof(key)) + 2;
            retval = eth_addr_from_string(cp, ea);
            break;
        }
    }
    fclose(stream);
    return retval;
}
