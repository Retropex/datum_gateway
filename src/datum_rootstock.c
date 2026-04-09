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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <curl/curl.h>
#include <jansson.h>

#include "datum_rootstock.h"
#include "datum_conf.h"
#include "datum_utils.h"
#include "datum_jsonrpc.h"

// Current RSK work, protected by rwlock
static T_DATUM_RSK_WORK rsk_current_work;
static pthread_rwlock_t rsk_work_lock = PTHREAD_RWLOCK_INITIALIZER;

// RSK notify counter
static uint64_t rsk_notify_id = 0;

// Thread handle
static pthread_t rsk_thread;
static bool rsk_thread_running = false;

// RSK RPC auth string
static char rsk_rpc_userpass[256];

static json_t *rsk_json_rpc_call(CURL *curl, const char *rpc_req) {
	if (rsk_rpc_userpass[0]) {
		return json_rpc_call(curl, datum_config.rootstock_rpcurl, rsk_rpc_userpass, rpc_req);
	}
	return json_rpc_call(curl, datum_config.rootstock_rpcurl, NULL, rpc_req);
}

// Parse the result of mnr_getWork
// Returns: array of [blockHashForMergedMining, target, ...]
// blockHashForMergedMining is 32 bytes hex (64 chars)
static bool rsk_parse_getwork(json_t *result, T_DATUM_RSK_WORK *work) {
	json_t *res_val;
	const char *block_hash_hex;
	const char *target_hex;
	size_t len;

	res_val = json_object_get(result, "result");
	if (!res_val || !json_is_array(res_val)) {
		DLOG_DEBUG("RSK mnr_getWork: result is not an array");
		return false;
	}

	if (json_array_size(res_val) < 2) {
		DLOG_DEBUG("RSK mnr_getWork: result array too short (%zu)", json_array_size(res_val));
		return false;
	}

	// First element: block hash for merged mining (hex string, 0x-prefixed)
	block_hash_hex = json_string_value(json_array_get(res_val, 0));
	if (!block_hash_hex) {
		DLOG_DEBUG("RSK mnr_getWork: blockHashForMergedMining is not a string");
		return false;
	}

	// Strip 0x prefix if present
	if (block_hash_hex[0] == '0' && block_hash_hex[1] == 'x') {
		block_hash_hex += 2;
	}

	len = strlen(block_hash_hex);
	if (len != 64) {
		DLOG_DEBUG("RSK mnr_getWork: blockHashForMergedMining has wrong length (%zu)", len);
		return false;
	}

	// Convert hex to binary
	for (int i = 0; i < 32; i++) {
		work->block_hash[i] = hex2bin_uchar(&block_hash_hex[i * 2]);
	}
	memcpy(work->block_hash_hex, block_hash_hex, 64);
	work->block_hash_hex[64] = 0;

	// Second element: target (hex string, 0x-prefixed)
	target_hex = json_string_value(json_array_get(res_val, 1));
	if (!target_hex) {
		DLOG_DEBUG("RSK mnr_getWork: target is not a string");
		return false;
	}

	if (target_hex[0] == '0' && target_hex[1] == 'x') {
		target_hex += 2;
	}

	len = strlen(target_hex);
	// Target may be shorter than 64 chars, pad with leading zeros
	memset(work->target, 0, 32);
	if (len <= 64) {
		int offset = 32 - (int)(len / 2);
		for (size_t i = 0; i < len / 2; i++) {
			work->target[offset + i] = hex2bin_uchar(&target_hex[i * 2]);
		}
	}

	work->has_work = true;
	work->work_tsms = current_time_millis();

	return true;
}

bool datum_rootstock_is_active(void) {
	return datum_config.rootstock_enable_rootstock && rsk_thread_running;
}

bool datum_rootstock_get_work(T_DATUM_RSK_WORK *out) {
	bool result = false;
	pthread_rwlock_rdlock(&rsk_work_lock);
	if (rsk_current_work.has_work) {
		memcpy(out, &rsk_current_work, sizeof(T_DATUM_RSK_WORK));
		result = true;
	}
	pthread_rwlock_unlock(&rsk_work_lock);
	return result;
}

uint64_t datum_rootstock_get_notify_id(void) {
	uint64_t id;
	pthread_rwlock_rdlock(&rsk_work_lock);
	id = rsk_notify_id;
	pthread_rwlock_unlock(&rsk_work_lock);
	return id;
}

int datum_rootstock_build_op_return_script(unsigned char *out) {
	T_DATUM_RSK_WORK work;

	if (!datum_rootstock_get_work(&work)) {
		return 0;
	}

	// OP_RETURN
	out[0] = 0x6a;
	// Push length: 9 (RSKBLOCK:) + 32 (hash) = 41 = 0x29
	out[1] = 0x29;
	// "RSKBLOCK:" tag
	memcpy(&out[2], RSK_TAG, RSK_TAG_LEN);
	// RSK block info (32 bytes)
	memcpy(&out[2 + RSK_TAG_LEN], work.block_hash, RSK_BLOCK_INFO_LEN);

	return RSK_OP_RETURN_SCRIPT_LEN;
}

void *datum_rootstock_thread(void *arg) {
	(void)arg;
	CURL *curl;
	char rpc_req[256];
	json_t *result;
	T_DATUM_RSK_WORK new_work;
	uint64_t poll_interval_us;

	curl = curl_easy_init();
	if (!curl) {
		DLOG_ERROR("RSK: Could not initialize cURL for RSK polling");
		rsk_thread_running = false;
		return NULL;
	}

	poll_interval_us = (uint64_t)datum_config.rootstock_poll_interval * 1000000ULL;
	if (poll_interval_us < 1000000ULL) {
		poll_interval_us = 1000000ULL; // minimum 1 second
	}

	DLOG_INFO("RSK: Merged mining thread started, polling %s every %d seconds",
		datum_config.rootstock_rpcurl, datum_config.rootstock_poll_interval);

	while (1) {
		snprintf(rpc_req, sizeof(rpc_req),
			"{\"jsonrpc\":\"2.0\",\"method\":\"mnr_getWork\",\"params\":[],\"id\":%"PRIu64"}",
			(uint64_t)time(NULL));

		result = rsk_json_rpc_call(curl, rpc_req);

		if (result) {
			memset(&new_work, 0, sizeof(new_work));
			if (rsk_parse_getwork(result, &new_work)) {
				pthread_rwlock_wrlock(&rsk_work_lock);
				// Check if the work actually changed
				if (memcmp(rsk_current_work.block_hash, new_work.block_hash, RSK_BLOCK_INFO_LEN) != 0) {
					memcpy(&rsk_current_work, &new_work, sizeof(T_DATUM_RSK_WORK));
					rsk_notify_id++;
					DLOG_DEBUG("RSK: New work received, hash=%s", rsk_current_work.block_hash_hex);
				} else {
					// Same work, just update timestamp
					rsk_current_work.work_tsms = new_work.work_tsms;
				}
				pthread_rwlock_unlock(&rsk_work_lock);
			} else {
				DLOG_DEBUG("RSK: Failed to parse mnr_getWork response");
			}
			json_decref(result);
		} else {
			DLOG_DEBUG("RSK: mnr_getWork RPC call failed");
		}

		usleep(poll_interval_us);
	}

	curl_easy_cleanup(curl);
	rsk_thread_running = false;
	return NULL;
}

void datum_rootstock_submit_solution(
	const uint8_t *block_header,
	const uint8_t *coinbase_txn,
	size_t coinbase_txn_size,
	const unsigned char merkle_hashes[][32],
	int merkle_count
) {
	CURL *curl;
	json_t *result;
	char *req = NULL;
	size_t req_sz;
	char *ptr;
	int i;

	if (!datum_rootstock_is_active()) return;

	curl = curl_easy_init();
	if (!curl) {
		DLOG_ERROR("RSK: Could not initialize cURL for RSK solution submission");
		return;
	}

	// Build mnr_submitBitcoinBlockPartialMerkle request
	// Parameters: [blockHashHex, blockHeaderHex, coinbaseHex, txnHashHex, merkleBranchCount, merkleBranchHashes]
	// Allocate enough space for the request
	// block_header hex = 160, coinbase hex = coinbase_txn_size*2, merkle hashes = merkle_count*64
	req_sz = 512 + 160 + (coinbase_txn_size * 2) + (merkle_count * 64) + 256;
	req = malloc(req_sz);
	if (!req) {
		DLOG_ERROR("RSK: Could not allocate memory for RSK submission");
		curl_easy_cleanup(curl);
		return;
	}

	ptr = req;

	// Get current RSK block hash
	T_DATUM_RSK_WORK work;
	if (!datum_rootstock_get_work(&work)) {
		DLOG_WARN("RSK: No RSK work available for submission");
		free(req);
		curl_easy_cleanup(curl);
		return;
	}

	ptr += sprintf(ptr, "{\"jsonrpc\":\"2.0\",\"method\":\"mnr_submitBitcoinBlockPartialMerkle\",\"params\":[\"0x%s\",\"0x",
		work.block_hash_hex);

	// Block header (80 bytes -> 160 hex chars)
	for (i = 0; i < 80; i++) {
		ptr += sprintf(ptr, "%02x", block_header[i]);
	}

	ptr += sprintf(ptr, "\",\"0x");

	// Coinbase transaction
	for (size_t j = 0; j < coinbase_txn_size; j++) {
		ptr += sprintf(ptr, "%02x", coinbase_txn[j]);
	}

	ptr += sprintf(ptr, "\",\"0x");

	// Build the partial merkle proof: concatenated merkle branch hashes
	for (i = 0; i < merkle_count; i++) {
		for (int j = 0; j < 32; j++) {
			ptr += sprintf(ptr, "%02x", merkle_hashes[i][j]);
		}
	}

	ptr += sprintf(ptr, "\",%d],\"id\":%"PRIu64"}", merkle_count, (uint64_t)time(NULL));

	DLOG_DEBUG("RSK: Submitting solution for RSK block %s", work.block_hash_hex);

	result = rsk_json_rpc_call(curl, req);
	if (result) {
		char *s = json_dumps(result, JSON_ENCODE_ANY);
		if (s) {
			DLOG_INFO("RSK: Solution submission response: %s", s);
			free(s);
		}
		json_decref(result);
	} else {
		DLOG_WARN("RSK: Solution submission RPC call failed");
	}

	free(req);
	curl_easy_cleanup(curl);
}

int datum_rootstock_init(void) {
	if (!datum_config.rootstock_enable_rootstock) {
		return 0;
	}

	if (!datum_config.rootstock_rpcurl[0]) {
		DLOG_ERROR("RSK: Rootstock merge mining enabled but no RPC URL configured");
		return -1;
	}

	// Build RPC auth string
	if (datum_config.rootstock_rpcuser[0]) {
		snprintf(rsk_rpc_userpass, sizeof(rsk_rpc_userpass), "%s:%s",
			datum_config.rootstock_rpcuser, datum_config.rootstock_rpcpassword);
	} else {
		rsk_rpc_userpass[0] = 0;
	}

	memset(&rsk_current_work, 0, sizeof(rsk_current_work));
	rsk_notify_id = 0;

	DLOG_INFO("RSK: Rootstock merged mining initialized (url=%s)", datum_config.rootstock_rpcurl);
	return 0;
}

void datum_rootstock_start(void) {
	if (!datum_config.rootstock_enable_rootstock) {
		return;
	}

	rsk_thread_running = true;
	if (pthread_create(&rsk_thread, NULL, datum_rootstock_thread, NULL) != 0) {
		DLOG_ERROR("RSK: Failed to start RSK polling thread");
		rsk_thread_running = false;
	}
}
