[![Build Status](https://travis-ci.org/Kuebler-IT/MeshVPN.svg?branch=master)](https://travis-ci.org/Kuebler-IT/MeshVPN)
[![BCH compliance](https://bettercodehub.com/edge/badge/Kuebler-IT/MeshVPN?branch=master)](https://bettercodehub.com/)

MeshVPN is a fork from PeerVPN to fix the not merged issues since a couple
of years. Some features are planned an will be updated in future.

## More about

MeshVPN is a software that builds virtual ethernet networks between multiple
computers. Such a virtual network can be useful to facilitate direct
communication that applications like file sharing or playing games may need.
Often, such direct communication is made impossible or very difficult by
firewalls or NAT devices.

Most traditional VPN solutions follow the client-server principle, which means
that all participating nodes connect to a central server. This creates a star
topology, which has some disadvantages. The central node needs lots of
bandwidth, because it needs to handle all the VPN traffic. Also, if the central
node goes down, the whole VPN is down too.

A virtual network built by MeshVPN uses a full mesh topology. All nodes talks
directly to each other, there is no need for a central server. If one node goes
down, the rest of the network is unaffected.

Configuring MeshVPN is easy. You just need to configure a network name,
a password and the contact information (IP address and port) of another
PeerVPN node. Adding a new node to an existing network doesn't require the
existing nodes to alter their configuration, because its IP address is
automatically distributed across the whole virtual network.

## Features

-   Ethernet tunneling support using TAP devices
-   IPv6 support
-   Full mesh network topology
-   No NAT reconfiguration necessary
-   Shared key encryption and authentication support

## Documentation

There is a small [tutorial](https://github.com/Kuebler-IT/meshvpn/wiki/Tutorial)
that explains how to setup a simple VPN. The configuration options are explained
in the sample meshvpn.conf that is bundled together with the program.

## Platforms & Dependencies

MeshVPN is available for Linux and FreeBSD. Additionally, one of the following
crypto libraries is required:

-   [LibreSSL](https://www.libressl.org) (recommended)
-   [OpenSSL](https://www.openssl.org) 1.0.X (note: the 1.1.x has incompatible API changes)

## License

MeshVPN is licensed under the terms of the GPLv3.

## Download

...

## Contact

If you have any questions or bug reports, open a issue ticket on github.com
