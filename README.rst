
EXPERIMENTAL: Ethernet over RTT for Linux
#########################################

This repository contains experimental program to communicate with
Ethernet RTT driver from nRF Connect SDK.

Dependencies
************

This software depends on **nrfjprog** from **nRF5 Command Line Tools**.

Build
*****

This program can be build using **make** command.

.. code-block:: bash

    # make NRFJPROG_PATH=/nrfjprog/path/

Parameter ``NRFJPROG_PATH=/nrfjprog/path/`` may be skipped if nrfjprog is
in your PATH variable.

It will generate ``eth_rtt_link`` program.
Following command will give more help:

.. code-block:: bash

    # ./eth_rtt_link --help

