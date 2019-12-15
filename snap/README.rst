Overview
========

A snap is a bundle of an app and its dependencies that works without
modification across many different Linux distributions.

Installing the OVN snap
-----------------------

.. code:: bash

    sudo snap install ovn

Granting access to system Open vSwitch
--------------------------------------

If you want to make use of the OVN snap on a data plane node and enable the
``controller`` serivce, you must grant the snap access to the database- and
bridge- sockets of your systems Open vSwitch service.

This is accomplished by executing the following command:

.. code:: bash

    sudo snap connect ovn:openvswitch

Configuring services
--------------------

The snap makes use of the ``ovn-ctl`` script to start and stop the OVN services.

You may influence which parameters are passed by adding arguments separated by 
space or newline to ``/var/snap/ovn/common/args_DAEMON``.

(Where *DAEMON* is one of ``controller``, ``controller_vtep``, ``northd``,
``nb-ovsdb``, ``sb-ovsdb``)

> **Note**: The arguments added to the ``args_northd`` file is passed directly
  to ``ovn-northd`` and not ``ovn-ctl``.  This is due to ``ovn-ctl`` not having
  the necessary knobs for configuring it with often used parameters such as
  placement of certificates for connecting to databases through TLS.

Controlling services
--------------------

Start and stop a daemon:

.. code:: bash

    sudo snap start ovn.DAEMON
    sudo snap stop ovn.DAEMON

(Where *DAEMON* is one of ``controller``, ``controller_vtep``, ``northd``,
``nb-ovsdb``, ``sb-ovsdb``)

Persist startup behaviour:

.. code:: bash

    sudo snap start --enable ovn.DAEMON
    sudo snap stop --disable ovn.DAEMON

Where is my data?
-----------------

The OVN snap is strictly confined and is with the exception of specific access
grants run in complete isolation from the hosting system.

This isolation is provided by the AppArmor Mandatory Access Control system and
the profiles mandates placement of data in specific places for OVN's
applications to have access to it.

You will find configuration, logs and persistent data in
``/var/snap/ovn/common``
