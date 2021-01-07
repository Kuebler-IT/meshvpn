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

#ifndef F_DH_C
#define F_DH_C


#include "crypto.h"
#include "dh.h"

#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

// Load DH parameters.
int dhLoadParams(struct s_dh_state *dhstate, unsigned char *dhpem, const int dhpem_size) {
	DH *dhptr = dhstate->dh;
	BIO *biodh;
	int ret;
	int err;
	if((dhpem_size > 0) && (dhpem != NULL)) {
		ret = 0;
		biodh = BIO_new_mem_buf(dhpem, dhpem_size);
		if(PEM_read_bio_DHparams(biodh, &dhptr, NULL, NULL) != NULL) {
			ret = DH_check(dhstate->dh, &err);
		}
		BIO_free(biodh);
		return ret;
	}
	else {
		return 0;
	}
}


// Load default DH parameters.
int dhLoadDefaultParams(struct s_dh_state *dhstate) {
	char *defaultdh = "-----BEGIN DH PARAMETERS-----\n\
MIIBCAKCAQEA06t5J/XwK39BbRJ5TyktEk+9VL3jHXlUgbnm6BEcdPAB+6h48gNN\n\
ZEAt0eFLK8hUWeO3BBqy6cLNfDWFRvoigVfZejnRaVXONWcviJJ1EGnYHI5m0Pw/\n\
qax1J/ceWEld2Fod74segxbLku1QS3h8x77RBjFcy4Fcq3pysjRPVaOrbEhQ/NHX\n\
Uo4jyN72bFgn1QYKVXoS513rtXalzw+gQFjB8zeL96b78mX2uG4VxDHQg519dXac\n\
sDMrJWqETGtTz3kprpETE9Vgh3dMHViMdwWe0+g8oX2EdNmMRrqm0VsWQBhMld6b\n\
CXzWzPkElg5L22pMUCPfYxo10HKoUHmSYwIBAg==\n\
-----END DH PARAMETERS-----\n";

	unsigned char *dhpem = (unsigned char *)defaultdh;
	const int dhpem_size = strlen(defaultdh);
	return dhLoadParams(dhstate, dhpem, dhpem_size);
}


// Generate a key.
int dhGenKey(struct s_dh_state *dhstate) {
	const BIGNUM *bn;
	int bn_size;
	if(DH_generate_key(dhstate->dh)) {
		DH_get0_key(dhstate->dh, &bn, NULL);
		bn_size = BN_num_bytes(bn);
		if((bn_size > dh_MINSIZE) && (bn_size < dh_MAXSIZE)) {
			BN_bn2bin(bn, dhstate->pubkey);
			dhstate->pubkey_size = bn_size;
			return 1;
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
}


// Create a DH state object.
int dhCreate(struct s_dh_state *dhstate) {
	dhstate->bn = BN_new();
	if(dhstate->bn != NULL) {
		BN_zero(dhstate->bn);
		dhstate->pubkey_size = 0;
		dhstate->dh = DH_new();
		if(dhstate->dh != NULL) {
			if(dhLoadDefaultParams(dhstate)) {
				if(dhGenKey(dhstate)) {
					return 1;
				}
			}
			DH_free(dhstate->dh);
		}
		BN_free(dhstate->bn);
	}
	return 0;
}


// Destroy a DH state object.
void dhDestroy(struct s_dh_state *dhstate) {
	DH_free(dhstate->dh);
	BN_free(dhstate->bn);
	dhstate->pubkey_size = 0;
}


// Get size of binary encoded DH public key in bytes.
int dhGetPubkeySize(const struct s_dh_state *dhstate) {
	return dhstate->pubkey_size;
}


// Get binary encoded DH public key. Returns length if successful.
int dhGetPubkey(unsigned char *buf, const int buf_size, const struct s_dh_state *dhstate) {
	int dhsize = dhGetPubkeySize(dhstate);
	if((dhsize > dh_MINSIZE) && (dhsize < buf_size)) {
		memcpy(buf, dhstate->pubkey, dhsize);
		return dhsize;
	}
	else {
		return 0;
	}
}


// Generate symmetric keys. Returns 1 if succesful.
int dhGenCryptoKeys(struct s_crypto *ctx, const int ctx_count, const struct s_dh_state *dhstate, const unsigned char *peerkey, const int peerkey_len, const unsigned char *nonce, const int nonce_len) {
	BIGNUM *bn = dhstate->bn;
	const BIGNUM *bn2;
	DH *dh = dhstate->dh;
	int ret = 0;
	int maxsize = DH_size(dh);
	unsigned char secret[maxsize];
	int size;
	BN_bin2bn(peerkey, peerkey_len, bn);
	DH_get0_key(dh, &bn2, NULL);
	if(BN_ucmp(bn, bn2) != 0) {
		size = DH_compute_key(secret, bn, dh);
		if(size > 0) {
			ret = cryptoSetKeys(ctx, ctx_count, secret, size, nonce, nonce_len);
		}
	}
	BN_zero(bn);
	return ret;
}


#endif // F_DH_C
