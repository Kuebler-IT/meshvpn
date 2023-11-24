/*
 * MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
 *
 * Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
 * Copyright (C) 2016       Hideman Developer <company@hideman.net>
 * Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef F_GLOBALS_C
#define F_GLOBALS_C

#include "io.h"
#include "p2p.h"
#include "ethernet.h"

struct s_io_state iostate;
struct s_p2psec * g_p2psec;
int g_mainloop;

struct s_switch_state g_switchstate;
struct s_ndp6_state g_ndpstate;
struct s_virtserv_state g_virtserv;

int g_enableconsole;
int g_enableeth;
int g_enablendpcache;
int g_enablevirtserv;
int g_enableengines;

#endif
