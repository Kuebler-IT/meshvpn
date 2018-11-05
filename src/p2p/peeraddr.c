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

#ifndef F_PEERADDR_C
#define F_PEERADDR_C


#include "util.h"
#include "string.h"
#include <arpa/inet.h>
#include "p2p.h"
#include "io.h"


// Returns true if PeerAddr is internal.
int peeraddrIsInternal(const struct s_peeraddr *peeraddr) {
	int i;
	i = utilReadInt32(&peeraddr->addr[0]);
	if(i == 0) {
		return 1;
	}
	else {
		return 0;
	}
}


// Returns type of internal PeerAddr or -1 if it is not internal.
int peeraddrGetInternalType(const struct s_peeraddr *peeraddr) {
	if(peeraddrIsInternal(peeraddr)) {
		return utilReadInt32(&peeraddr->addr[4]);
	}
	else {
		return -1;
	}
}


// Get indirect PeerAddr attributes. Returns 1 on success or 0 if the PeerAddr is not indirect.
int peeraddrGetIndirect(const struct s_peeraddr *peeraddr, int *relayid, int *relayct, int *peerid) {
	if(peeraddrGetInternalType(peeraddr) != peeraddr_INTERNAL_INDIRECT) {
		return 0;
	}

	if(relayid != NULL) {
		*relayid = utilReadInt32(&peeraddr->addr[8]);
	}

	if(relayct != NULL) {
		*relayct = utilReadInt32(&peeraddr->addr[12]);
	}

	if(peerid != NULL) {
		*peerid = utilReadInt32(&peeraddr->addr[16]);
	}
	return 1;
}


// Construct indirect PeerAddr.
void peeraddrSetIndirect(struct s_peeraddr *peeraddr, const int relayid, const int relayct, const int peerid) {
	utilWriteInt32(&peeraddr->addr[0], 0);
	utilWriteInt32(&peeraddr->addr[4], peeraddr_INTERNAL_INDIRECT);
	utilWriteInt32(&peeraddr->addr[8], relayid);
	utilWriteInt32(&peeraddr->addr[12], relayct);
	utilWriteInt32(&peeraddr->addr[16], peerid);
	utilWriteInt32(&peeraddr->addr[20], 0);
}

/**
 * Copy human readable peer address to buffer
 */
void peeraddrToHuman(char * buffer, const struct s_peeraddr * peeraddr) {
    char res[64];
    if(memcmp(&peeraddr->addr[0], IO_ADDRTYPE_UDP6, 4) == 0) {
        inet_ntop(AF_INET6, &peeraddr->addr[4], res, 64);
    } else {
        inet_ntop(AF_INET, &peeraddr->addr[4], res, 64);
    }

    if(peeraddrGetInternalType(peeraddr) == peeraddr_INTERNAL_INDIRECT) {
        strcpy(buffer, "INDIRECT");
    } else {
        strcpy(buffer, res);
    }
}


#endif // F_PEERADDR_C
