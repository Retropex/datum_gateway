/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _DATUM_ROOTSTOCK_H_
#define _DATUM_ROOTSTOCK_H_

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

// RSK merged mining OP_RETURN format:
// OP_RETURN (0x6a) + Length (0x29 = 41) + "RSKBLOCK:" (9 bytes) + RskBlockInfo (32 bytes)
// Total script: 43 bytes, total output: 43 + 8 (value) + 1 (script_len) = 52 bytes
#define RSK_TAG "RSKBLOCK:"
#define RSK_TAG_LEN 9
#define RSK_BLOCK_INFO_LEN 32
#define RSK_OP_RETURN_SCRIPT_LEN 43  // 1 (OP_RETURN) + 1 (push len) + 9 (tag) + 32 (hash)
#define RSK_OP_RETURN_OUTPUT_LEN 52  // 8 (value=0) + 1 (script_len) + 43 (script)

typedef struct {
	// Current RSK block hash from mnr_getWork (32 bytes binary)
	unsigned char block_hash[RSK_BLOCK_INFO_LEN];
	char block_hash_hex[65];

	// RSK target for merged mining difficulty
	unsigned char target[RSK_BLOCK_INFO_LEN];

	// Whether we have valid RSK work
	bool has_work;

	// Timestamp of when this work was fetched
	uint64_t work_tsms;

	// Notify counter - incremented when new RSK work arrives
	uint64_t notify_id;
} T_DATUM_RSK_WORK;

// Initialize the RSK merged mining subsystem
int datum_rootstock_init(void);

// Start the RSK work polling thread
void datum_rootstock_start(void);

// Get the current RSK work (thread-safe)
// Returns true if valid RSK work is available
bool datum_rootstock_get_work(T_DATUM_RSK_WORK *out);

// Get the current RSK notify ID (for detecting work changes)
uint64_t datum_rootstock_get_notify_id(void);

// Check if RSK merged mining is enabled and active
bool datum_rootstock_is_active(void);

// Build the RSK OP_RETURN output script (binary) for inclusion in the coinbase
// Returns the script length, or 0 if RSK is not active
// out must be at least RSK_OP_RETURN_SCRIPT_LEN bytes
int datum_rootstock_build_op_return_script(unsigned char *out);

// Submit a Bitcoin block to the RSK node for merged mining credit
// block_header: 80-byte Bitcoin block header
// coinbase_txn: full coinbase transaction binary
// coinbase_txn_size: size of coinbase transaction
// merkle_hashes: merkle branch hashes (array of 32-byte hashes)
// merkle_count: number of merkle branch entries
void datum_rootstock_submit_solution(
	const uint8_t *block_header,
	const uint8_t *coinbase_txn,
	size_t coinbase_txn_size,
	const unsigned char merkle_hashes[][32],
	int merkle_count
);

// RSK work polling thread function
void *datum_rootstock_thread(void *arg);

#endif
