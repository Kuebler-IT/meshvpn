#
# MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
#
# Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
# Copyright (C) 2016       Hideman Developer <company@hideman.net>
# Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

sbin_PROGRAMS = meshvpn

meshvpn_SOURCES = \
	encryption/rsa.c \
	encryption/crypto.c \
	encryption/dh.c \
	p2p/idsp.c \
	p2p/auth.c \
	p2p/nodeid.c \
	p2p/nodedb.c \
	p2p/peeraddr.c \
	p2p/peermgt.c \
	p2p/authmgt.c \
	p2p/packet.c \
	p2p/dfrag.c \
	p2p/p2psec.c \
	p2p/netid.c \
	p2p/seq.c \
	platform/io.c \
	platform/seccomp.c \
	platform/perms.c \
	platform/ifconfig.c \
	app/globals.c \
	app/init.c \
	app/loop.c \
	app/config.c \
	app/util.c \
	app/map.c \
	app/logging.c \
	app/console.c \
	ethernet/checksum.c \
	ethernet/ndp6.c \
	ethernet/switch.c \
	ethernet/virtserv.c \
	meshvpn.c
