/*
***** ZiftrCOIN Hashing Algo Module  by ocminer (admin at suprnova.cc)  ******
*/

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_blake.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"

#define ZR_BLAKE   0
#define ZR_GROESTL 1
#define ZR_JH      2
#define ZR_SKEIN   3
 
#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

static void ziftrhash(void *state, const void *input)
{

    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

    static unsigned char pblank[1];
    pblank[0] = 0;

    // Pre-computed table of permutations
    static const int arrOrder[][4] =
    {
        {0, 1, 2, 3},
        {0, 1, 3, 2},
        {0, 2, 1, 3},
        {0, 2, 3, 1},
        {0, 3, 1, 2},
        {0, 3, 2, 1},
        {1, 0, 2, 3},
        {1, 0, 3, 2},
        {1, 2, 0, 3},
        {1, 2, 3, 0},
        {1, 3, 0, 2},
        {1, 3, 2, 0},
        {2, 0, 1, 3},
        {2, 0, 3, 1},
        {2, 1, 0, 3},
        {2, 1, 3, 0},
        {2, 3, 0, 1},
        {2, 3, 1, 0},
        {3, 0, 1, 2},
        {3, 0, 2, 1},
        {3, 1, 0, 2},
        {3, 1, 2, 0},
        {3, 2, 0, 1},
        {3, 2, 1, 0}
    };


    uint32_t hash[32];

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 80);
    sph_keccak512_close(&ctx_keccak, (&hash));

    unsigned int nOrder = *(unsigned int *)(&hash) % 24;

    unsigned int i = 0;

    for (i = 0; i < 4; i++)
    {

        switch (arrOrder[nOrder][i])
        {
        case 0:
            sph_blake512_init(&ctx_blake);
            sph_blake512 (&ctx_blake, (&hash), 64);
            sph_blake512_close(&ctx_blake, (&hash));
            break;
        case 1:
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512 (&ctx_groestl, (&hash), 64);
            sph_groestl512_close(&ctx_groestl, (&hash));
            break;
        case 2:
            sph_jh512_init(&ctx_jh);
            sph_jh512 (&ctx_jh, (&hash), 64);
            sph_jh512_close(&ctx_jh, (&hash));
            break;
        case 3:
            sph_skein512_init(&ctx_skein);
            sph_skein512 (&ctx_skein, (&hash), 64);
            sph_skein512_close(&ctx_skein, (&hash));
            break;
        default:
            break;
        }
    }

	memcpy(state, hash, 32);
}

int scanhash_ziftr(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{

	uint32_t hash[16] __attribute__((aligned(64)));
	uint32_t tmpdata[20] __attribute__((aligned(64)));

	const uint32_t version = pdata[0] & (~POK_DATA_MASK);
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
 
	memcpy(tmpdata, pdata, 80);
 
	do {
		#define Htarg ptarget[7]
 
		tmpdata[0]  = version;
		tmpdata[19] = nonce;
		ziftrhash(hash, tmpdata);
		tmpdata[0] = version | (hash[0] & POK_DATA_MASK);
		ziftrhash(hash, tmpdata);
 
		if (hash[7] <= Htarg && fulltest(hash, ptarget))
		{
			pdata[0] = tmpdata[0];
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce + 1;
			if (opt_debug)
				applog(LOG_INFO, "found nonce %x", nonce);
			return 1;
		}
		nonce++;
 
	} while (nonce < max_nonce && !work_restart[thr_id].restart);
 
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;

}

