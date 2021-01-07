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

#ifndef F_P2PSEC_C
#define F_P2PSEC_C


#include "p2p.h"
#include "logging.h"
#include "rsa.h"
#include "platform.h"
#include "map.h"
#include <unistd.h>

int p2psecStart(struct s_p2psec *p2psec) {
	if(!cryptoRandInit()) {
		return 0;
	}

	if (!((!p2psec->started) && (p2psec->key_loaded) && (p2psec->dh_loaded))) {
		return 0;
	}

	if(!(peermgtCreate(&p2psec->mgt, p2psec->peer_count, p2psec->auth_count, &p2psec->nk, &p2psec->dh))) {
		return 0;
	}

	peermgtSetLoopback(&p2psec->mgt, p2psec->loopback_enable);
	peermgtSetFastauth(&p2psec->mgt, p2psec->fastauth_enable);
	peermgtSetFragmentation(&p2psec->mgt, p2psec->fragmentation_enable);
	peermgtSetNetID(&p2psec->mgt, p2psec->netname, p2psec->netname_len);
	peermgtSetPassword(&p2psec->mgt, p2psec->password, p2psec->password_len);
	peermgtSetFlags(&p2psec->mgt, p2psec->flags);
	p2psec->started = 1;

	return 1;
}


void p2psecStop(struct s_p2psec *p2psec) {
	if(!p2psec->started) return;

	peermgtDestroy(&p2psec->mgt);
	p2psec->started = 0;
}


int p2psecGetAddrSize() {
	return peeraddr_SIZE;
}


int p2psecGetNodeIDSize() {
	return nodeid_SIZE;
}

/**
 * Initialize node private keys. If there is no file by keypath we will generate keys and export them to file
 * otherwise we will try to load it.
 * keypath - should be writable path, might be in chrooted dir, because private keys readed before priveleges revoke
 */
int p2psecInitPrivateKey(struct s_p2psec *p2psec, const int bits, const char *keypath) {
    if(strlen(keypath) > 0) {
        debugf("Initialize  encryption keys, save path is %s", keypath);
    }

    if(access(keypath, F_OK) == 0) {
        debug("PEM file found. Loading it.");
        if(p2psecImportPrivkey(p2psec, keypath)) {
            msgf("PEM file successfully loaded: %s", keypath);
            return 1;
        }

        debugf("Failed to import key from %s, will be regenerated", keypath);
    }

    if(!p2psecGeneratePrivkey(p2psec, bits)) {
        debug("failed to generate private key");
        return 0;
    }

    if(!p2psecExportPrivkey(p2psec, keypath)){
        debugf("Failed to export private key to %s", keypath);
        return 0;
    }

    return 1;
}

int p2psecImportPrivkey(struct s_p2psec * p2psec, const char * keypath) {
    if(!nodekeyCreate(&p2psec->nk)) {
        debug("failed to initialize node key");
        return 0;
    }

    if(!nodekeyImport(&p2psec->nk, keypath)) {
        debug("PEM key import failed");
        return 0;
    }

    p2psec->key_loaded = 1;
    return 1;
}
/**
 * Export key to
 */
int p2psecExportPrivkey(struct s_p2psec * p2psec, const char * keypath) {
    if(!p2psec->key_loaded) {
        debug("unable to save key because it's not loaded!");
        return 0;
    }

    if(!nodekeyExport(&p2psec->nk, keypath)) {
        debug("failed to export RSA key");
        return 0;
    }

    debug("Encryption key successfully exported");
    return 1;
}

/**
 * Generate or load private key from file
 */
int p2psecGeneratePrivkey(struct s_p2psec *p2psec, const int bits) {
	if(p2psec->key_loaded) nodekeyDestroy(&p2psec->nk);

	if(bits >= 1024 && bits <= 3072) {
		if(nodekeyCreate(&p2psec->nk)) {
			if(nodekeyGenerate(&p2psec->nk, bits)) {
				p2psec->key_loaded = 1;
				return 1;
			}
			nodekeyDestroy(&p2psec->nk);
		}
	}
	p2psec->key_loaded = 0;
	return 0;
}


int p2psecLoadDH(struct s_p2psec *p2psec) {
	if(p2psec->dh_loaded) return 1;
	if(dhCreate(&p2psec->dh)) {
		p2psec->dh_loaded = 1;
		return 1;
	}
	return 0;
}


void p2psecSetMaxConnectedPeers(struct s_p2psec *p2psec, const int peer_count) {
	if(peer_count > 0) p2psec->peer_count = peer_count;

}


void p2psecSetAuthSlotCount(struct s_p2psec *p2psec, const int auth_slot_count) {
	if(auth_slot_count > 0) p2psec->auth_count = auth_slot_count;
}


void p2psecSetNetname(struct s_p2psec *p2psec, const char *netname, const int netname_len) {
	int len;
	if(netname_len < 1024) {
		len = netname_len;
	}
	else {
		len = 1023;
	}
	memset(p2psec->netname, 0, 1024);
	if(len > 0) {
		utilStringFilter(p2psec->netname, netname, len);
		p2psec->netname_len = len;
	}
	else {
		memcpy(p2psec->netname, "default", 7);
		p2psec->netname_len = 7;
	}

    debugf("Network name update to %s", p2psec->netname);
	if(p2psec->started) peermgtSetNetID(&p2psec->mgt, p2psec->netname, p2psec->netname_len);
}


void p2psecSetPassword(struct s_p2psec *p2psec, const char *password, const int password_len) {
    int len = (password_len < 1024) ? password_len : 1023;

	memset(p2psec->password, 0, 1024);
	if(len > 0) {
		memcpy(p2psec->password, password, len);
		p2psec->password_len = len;
	}
	else {
		memcpy(p2psec->password, "default", 7);
		p2psec->password_len = 7;
	}
	if(p2psec->started) peermgtSetPassword(&p2psec->mgt, p2psec->password, p2psec->password_len);
}


void p2psecEnableLoopback(struct s_p2psec *p2psec) {
	p2psec->loopback_enable = 1;
	if(p2psec->started) peermgtSetLoopback(&p2psec->mgt, 1);
}


void p2psecDisableLoopback(struct s_p2psec *p2psec) {
	p2psec->loopback_enable = 0;
	if(p2psec->started) peermgtSetLoopback(&p2psec->mgt, 0);
}


void p2psecEnableFastauth(struct s_p2psec *p2psec) {
	p2psec->fastauth_enable = 1;
	if(p2psec->started) peermgtSetFastauth(&p2psec->mgt, 1);
}


void p2psecDisableFastauth(struct s_p2psec *p2psec) {
	p2psec->fastauth_enable = 0;
	if(p2psec->started) peermgtSetFastauth(&p2psec->mgt, 0);
}


void p2psecEnableFragmentation(struct s_p2psec *p2psec) {
	p2psec->fragmentation_enable = 1;
	if(p2psec->started) peermgtSetFragmentation(&p2psec->mgt, 1);
}


void p2psecDisableFragmentation(struct s_p2psec *p2psec) {
	p2psec->fragmentation_enable = 0;
	if(p2psec->started) peermgtSetFragmentation(&p2psec->mgt, 0);
}


void p2psecSetFlag(struct s_p2psec *p2psec, const int flag, const int enable) {
	int f;
	if(enable) {
		f = (p2psec->flags | flag);
	}
	else {
		f = (p2psec->flags & (~flag));
	}
	p2psec->flags = f;
	if(p2psec->started) peermgtSetFlags(&p2psec->mgt, f);
}


void p2psecEnableUserdata(struct s_p2psec *p2psec) {
	p2psecSetFlag(p2psec, peermgt_FLAG_USERDATA, 1);
}


void p2psecDisableUserdata(struct s_p2psec *p2psec) {
	p2psecSetFlag(p2psec, peermgt_FLAG_USERDATA, 0);
}


void p2psecEnableRelay(struct s_p2psec *p2psec) {
	p2psecSetFlag(p2psec, peermgt_FLAG_RELAY, 1);
}


void p2psecDisableRelay(struct s_p2psec *p2psec) {
	p2psecSetFlag(p2psec, peermgt_FLAG_RELAY, 0);
}


int p2psecLoadDefaults(struct s_p2psec *p2psec) {
	if(!p2psecLoadDH(p2psec)) return 0;
	p2psecSetFlag(p2psec, (~(0)), 0);
	p2psecSetMaxConnectedPeers(p2psec, 65536);
	p2psecSetAuthSlotCount(p2psec, 32);
	p2psecDisableLoopback(p2psec);
	p2psecEnableFastauth(p2psec);
	p2psecDisableFragmentation(p2psec);
	p2psecEnableUserdata(p2psec);
	p2psecDisableRelay(p2psec);
	p2psecSetNetname(p2psec, NULL, 0);
	p2psecSetPassword(p2psec, NULL, 0);
	return 1;
}


struct s_p2psec *p2psecCreate() {
	struct s_p2psec *p2psec;
	p2psec = malloc(sizeof(struct s_p2psec));
	if(p2psec != NULL) {
		p2psec->started = 0;
		p2psec->key_loaded = 0;
		p2psec->dh_loaded = 0;
		p2psec->flags = 0;
		p2psecLoadDefaults(p2psec);
		return p2psec;
	}
	return NULL;
}


void p2psecDestroy(struct s_p2psec *p2psec) {
	p2psecStop(p2psec);
	if(p2psec->key_loaded) nodekeyDestroy(&p2psec->nk);
	if(p2psec->dh_loaded) dhDestroy(&p2psec->dh);
	p2psec->started = 0;
	p2psec->key_loaded = 0;
	p2psec->dh_loaded = 0;
	memset(p2psec->password, 0, 1024);
	p2psec->password_len = 0;
	memset(p2psec->netname, 0, 1024);
	p2psec->netname_len = 0;
	free(p2psec);
}


void p2psecStatus(struct s_p2psec *p2psec, char *status_report, const int status_report_len) {
	peermgtStatus(&p2psec->mgt, status_report, status_report_len);
}


void p2psecNodeDBStatus(struct s_p2psec *p2psec, char *status_report, const int status_report_len) {
	nodedbStatus(&p2psec->mgt.nodedb, status_report, status_report_len);
}


int p2psecConnect(struct s_p2psec *p2psec, const unsigned char *destination_addr) {
    debugf("P2P connection to %s", destination_addr);
	struct s_peeraddr addr;
	memcpy(addr.addr, destination_addr, peeraddr_SIZE);
	return peermgtConnect(&p2psec->mgt, &addr);
}


int p2psecInputPacket(struct s_p2psec *p2psec, const unsigned char *packet_input, const int packet_input_len, const unsigned char *packet_source_addr) {
	struct s_peeraddr addr;
	memcpy(addr.addr, packet_source_addr, peeraddr_SIZE);
	return peermgtDecodePacket(&p2psec->mgt, packet_input, packet_input_len, &addr);
}


unsigned char *p2psecRecvMSG(struct s_p2psec *p2psec, unsigned char *source_nodeid, int *message_len) {
	struct s_msg msg;
	struct s_nodeid nodeid;
    char nodeIdHuman[NODEID_SIZE + 1];

	if(peermgtRecvUserdata(&p2psec->mgt, &msg, &nodeid, NULL, NULL)) {
		*message_len = msg.len;
		if(source_nodeid != NULL) memcpy(source_nodeid, nodeid.id, NODEID_SIZE);
        nodeidExtract(nodeIdHuman, &nodeid);

        debugf("[%s] Recieved MSG", nodeIdHuman);

		return msg.msg;
	}
	else {
		return NULL;
	}
}


unsigned char *p2psecRecvMSGFromPeerID(struct s_p2psec *p2psec, int *source_peerid, int *source_peerct, int *message_len) {
	struct s_msg msg;
	if(peermgtRecvUserdata(&p2psec->mgt, &msg, NULL, source_peerid, source_peerct)) {
		*message_len = msg.len;
		return msg.msg;
	}
	else {
		return NULL;
	}
}


int p2psecSendMSG(struct s_p2psec *p2psec, const unsigned char *destination_nodeid, unsigned char *message, int message_len) {
	struct s_msg msg = { .msg = message, .len = message_len };
	struct s_nodeid nodeid;
	memcpy(nodeid.id, destination_nodeid, nodeid_SIZE);
	return peermgtSendUserdata(&p2psec->mgt, &msg, &nodeid, -1, -1);
}


int p2psecSendBroadcastMSG(struct s_p2psec *p2psec, unsigned char *message, int message_len) {
	struct s_msg msg = { .msg = message, .len = message_len };
	return peermgtSendBroadcastUserdata(&p2psec->mgt, &msg);
}


int p2psecSendMSGToPeerID(struct s_p2psec *p2psec, const int destination_peerid, const int destination_peerct, unsigned char *message, int message_len) {
	struct s_msg msg = { .msg = message, .len = message_len };
	return peermgtSendUserdata(&p2psec->mgt, &msg, NULL, destination_peerid, destination_peerct);
}


int p2psecOutputPacket(struct s_p2psec *p2psec, unsigned char *packet_output, const int packet_output_len, unsigned char *packet_destination_addr) {
	struct s_peeraddr addr;
	int len = peermgtGetNextPacket(&p2psec->mgt, packet_output, packet_output_len, &addr);
	if(len > 0) {
		memcpy(packet_destination_addr, addr.addr, peeraddr_SIZE);
		return len;
	}
	else {
		return 0;
	}
}


int p2psecPeerCount(struct s_p2psec *p2psec) {
	int n = peermgtPeerCount(&p2psec->mgt);
	return n;
}


int p2psecUptime(struct s_p2psec *p2psec) {
	if(p2psec == NULL) { return 0; }
	int uptime = peermgtUptime(&p2psec->mgt);
	return uptime;
}


#endif // F_P2PSEC_C
