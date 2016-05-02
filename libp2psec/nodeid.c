/***************************************************************************
 *   Copyright (C) 2012 by Tobias Volk                                     *
 *   mail@tobiasvolk.de                                                    *
 *                                                                         *
 *   This program is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/


#ifndef F_NODEID_C
#define F_NODEID_C
#include "../include/rsa.h"

#define NODEID_SIZE 32

// NodeID size in bytes.
#define nodeid_SIZE 32


// Maximum and minumum sizes of DER encoded NodeKey in bytes.
#define nodekey_MINSIZE RSA_MINSIZE
#define nodekey_MAXSIZE RSA_MAXSIZE


// The nodeid structure.
struct s_nodeid {
	unsigned char id[NODEID_SIZE];
};


// The nodekey structure.
struct s_nodekey {
	struct s_nodeid nodeid;
	struct s_rsa key;
};

static int nodeidExtract(char * buffer, struct s_nodeid * node) {
    memcpy(buffer, node->id, NODEID_SIZE);
    buffer[NODEID_SIZE] = '\0';
}

// Create a NodeKey object.
static int nodekeyCreate(struct s_nodekey *nodekey) {
	return rsaCreate(&nodekey->key);
}


// Get DER encoded public key from NodeKey object. Returns length if successful.
static int nodekeyGetDER(unsigned char *buf, const int buf_size, const struct s_nodekey *nodekey) {
	return rsaGetDER(buf, buf_size, &nodekey->key);
}


// Generate a new NodeKey with public/private key pair. 
static int nodekeyGenerate(struct s_nodekey *nodekey, const int key_size) {
	if(!rsaGenerate(&nodekey->key, key_size)) {
        return 0;
    }
    
    return rsaGetFingerprint(nodekey->nodeid.id, NODEID_SIZE, &nodekey->key);
}

/**
 * Export nodekey to file
 */
int nodekeyExport(struct s_nodekey * nodekey, const char * keypath) {
    return rsaExportKey(&nodekey->key, keypath);
}

int nodekeyImport(struct s_nodekey * nodekey, const char * keypath) {
    if(!rsaImportKey(&nodekey->key, keypath)) {
        debug("failed to import RSA key");
        return 0;
    }
    
    return rsaGetFingerprint(nodekey->nodeid.id, NODEID_SIZE, &nodekey->key);
}


// Load NodeKey from DER encoded public key.
static int nodekeyLoadDER(struct s_nodekey *nodekey, const unsigned char *pubkey, const int pubkey_size) {
	if(!rsaLoadDER(&nodekey->key, pubkey, pubkey_size)) {
        return 0;
    }
    
    return rsaGetFingerprint(nodekey->nodeid.id, NODEID_SIZE, &nodekey->key);
}


// Load NodeKey from PEM encoded public key.
static int nodekeyLoadPEM(struct s_nodekey *nodekey, unsigned char *pubkey, const int pubkey_size) {
	if(rsaLoadPEM(&nodekey->key, pubkey, pubkey_size)) {
		return rsaGetFingerprint(nodekey->nodeid.id, NODEID_SIZE, &nodekey->key);
	}
	else {
		return 0;
	}
}


// Load NodeKey from PEM encoded private key.
static int nodekeyLoadPrivatePEM(struct s_nodekey *nodekey, unsigned char *privkey, const int privkey_size) {
	if(rsaLoadPrivatePEM(&nodekey->key, privkey, privkey_size)) {
		return rsaGetFingerprint(nodekey->nodeid.id, nodeid_SIZE, &nodekey->key);
	}
	else {
		return 0;
	}
}


// Destroy a NodeKey object.
static void nodekeyDestroy(struct s_nodekey *nodekey) {
	rsaDestroy(&nodekey->key);
}



#endif // F_NODEID_C
