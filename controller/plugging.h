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

#ifndef OVN_PLUGGING_H
#define OVN_PLUGGING_H 1

/* Interface Plugging
 * ==================
 *
 * This module adds and removes ports on the integration bridge, as directed by
 * Port_Binding options.
 *
 * Traditionally it has been the CMSs responsibility to create Virtual
 * Interfaces as part of instance (Container, Pod, Virtual Machine etc.) life
 * cycle, and subsequently manage plug/unplug operations on the Open vSwitch
 * integration bridge.
 *
 * With the advent of NICs connected to multiple distinct CPUs we can have a
 * topology where the instance runs on one host and Open vSwitch and OVN runs
 * on a different host, the smartnic CPU.
 *
 * The act of plugging and unplugging the representor port in Open vSwitch
 * running on the smartnic host CPU would be the same for every smartnic
 * variant (thanks to the devlink-port infrastructure), and every CMS. As
 * such it is natural to extend OVN to provide this common functionality
 * through its CMS facing API.
 *
 * The instance will be connected to a SR-IOV Virtual Function or a RDMA
 * Mediated Device on the host sytem (the latter not currently addressed in
 * this implementation). The NIC driver will maintain a representor port for
 * each of the host visible devices on the smartnic side.
 *
 * It is the CMSs responsibility to maintain a mapping between instance host
 * and smartnic host, OVN can help by optionally providing details such as
 * board serial number of the smartnic system as part of Chassis registration.
 *
 * The CMS will use it's knowledge of instance host <-> smartnic host mapping
 * to add appropriate `requested-chassis` along with the information OVN needs
 * to identify the representor port as options when creating Logical Switch
 * Ports for instances. These options will be copied over to the Port_Binding
 * table by ovn-northd.
 *
 * OVN will use the devlink interface to look up which representor port
 * corresponds to the host visible resource and add this representor port to
 * the integration bridge.
 *
 * Options API:
 *   ovn-plugged: true
 *   pf-mac: "00:53:00:00:00:42" // To distinguish between ports on NIC SoC
 *   vf-num: 42 (optional)       // Refers to a logical PCI VF number
 *                               // not specifying vf-num means plug PF
 *                               // representor.
 */

struct ovsdb_idl_txn;
struct sbrec_port_binding_table;
struct ovsrec_port_table;
struct ovsrec_bridge;
struct sbrec_chassis;

void plugging_run(struct ovsdb_idl_txn *,
             const struct sbrec_port_binding_table *,
             const struct ovsrec_port_table *,
             const struct ovsrec_bridge *,
             const struct sbrec_chassis *);
void plugging_init(void);
void plugging_destroy(void);

#endif /* controller/plugging.h */
