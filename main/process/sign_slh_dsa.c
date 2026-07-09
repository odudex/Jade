#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"
#include "process_utils.h"
#include "../slh_dsa/slh_dsa.h"
#include "../slh_dsa/slh_param.h"
#include "../storage.h"
#include "utils/malloc_ext.h"
#include <mbedtls/sha512.h>

void slh_dsa_key_gen_process(void* process_ptr)
{
    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "slh_dsa_key_gen");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    uint8_t bytes[32];
    size_t bytes_len = 0;
    rpc_get_bytes("bytes", 32, &params, bytes, &bytes_len);
    if (bytes_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Expected 32-byte seed");
        goto cleanup;
    }

    uint8_t sha512_out[64];
    mbedtls_sha512(bytes, 32, sha512_out, 0);

    bool is_standard;
    rpc_get_boolean("is_standard", &params, &is_standard);
    
    slh_param_t prm;
    if (is_standard) {
        prm = slh_dsa_sha2_128s;
    } else {
        memcpy(&prm, &slh_dsa_sha2_128s, sizeof(slh_param_t));
        prm.alg_id = "custom-slh-dsa";
        prm.h = 45;
        prm.d = 5;
        prm.hp = 9;
        prm.a = 13;
        prm.k = 10;
        prm.lg_w = 4;
    }

    uint32_t n = prm.n;

    uint8_t sk[64];
    uint8_t pk[32];

    // Capture the top-layer tree leaves: [pk_root(n) || leaves(2^hp * n)]
    const size_t leaves_len = n + ((size_t)n << prm.hp);
    uint8_t* leaves = JADE_MALLOC(leaves_len);

    slh_keygen_internal(sk, pk,
        sha512_out,
        sha512_out + n,
        sha512_out + 2 * n,
        &prm,
        leaves + n);

    // Prefix with pk_root as the cache fingerprint, and persist to NVS
    memcpy(leaves, pk + n, n);
    if (!storage_set_slh_leaves(is_standard, leaves, leaves_len)) {
        JADE_LOGE("Failed to persist slh-dsa leaf cache");
    }
    free(leaves);

    jade_process_reply_to_message_bytes(&process->ctx, sk, sizeof(sk));

cleanup:
    return;
}

static void slh_dsa_progress_adapter(uint16_t current, void* userdata)
{
    progress_bar_t* pb = (progress_bar_t*)userdata;
    update_progress_bar(pb, 1000, current);
}

void sign_slh_dsa_process(void* process_ptr)
{
    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "sign_slh_dsa");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    uint8_t* sig_output = NULL;
    gui_activity_t* act = NULL;
    progress_bar_t pb = {};

    uint8_t message[32];
    size_t msg_len = 0;
    rpc_get_bytes("message", 32, &params, message, &msg_len);
    if (msg_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Missing message");
        goto cleanup;
    }

    bool is_standard;
    rpc_get_boolean("is_standard", &params, &is_standard);

    // rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);

    char msg_display[MAX_DISPLAY_MESSAGE_LEN];
    if (msg_len < MAX_DISPLAY_MESSAGE_LEN) {
        snprintf(msg_display, sizeof(msg_display), "%.*s", (int)msg_len, message);
    } else {
        snprintf(msg_display, sizeof(msg_display), "%.*s...", (int)sizeof(msg_display) - 4, message);
    }

    // const char* msg_lines[] = { "Sign message?", msg_display };
    // if (!await_yesno_activity("SLH-DSA", msg_lines, 2, false, NULL)) {
    //     jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined");
    //     goto cleanup;
    // }

    size_t written = 0;

    act = make_progress_bar_activity("Signing", "Please wait", &pb);
    gui_set_current_activity(act);
    
    slh_param_t prm;
    uint8_t sk_bytes[64];
    int ret;
    if (is_standard)
    { 
        prm = slh_dsa_sha2_128s;
        ret = wally_hex_to_bytes("0fac4b7b966f29c3ecff665eb4ead66eee253a1a3d501c09d2cc0a7a5afad4747906277af176f5e3cf644f591fb353c5d12447a500c02be7d4c86bd1e29a84ab", sk_bytes, sizeof(sk_bytes), &written);
    }
    else
    {
        memcpy(&prm, &slh_dsa_sha2_128s, sizeof(slh_param_t));
        prm.alg_id = "custom-slh-dsa";
        prm.h = 45;  
        prm.d = 5;  
        prm.hp = 9;
        prm.a = 13;   
        prm.k = 10;
        prm.lg_w = 4;

        ret = wally_hex_to_bytes("e39c0e870f7e0270c5e8bc4ecb8447f59acf02c625e6da1e2018140412e2c8d69fc70fec2531104d439e8409a144308e99a230a89e6ccc8fd40855d7f519029d", sk_bytes, sizeof(sk_bytes), &written);
    }

    if (ret != WALLY_OK || written != 64) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Sign failed");
        goto cleanup;
    }

    // Try to load the top-layer leaf cache saved at keygen; use it only if
    // its pk_root fingerprint matches this signing key (else sign without it)
    const size_t leaves_len = prm.n + ((size_t)prm.n << prm.hp);
    uint8_t* leaves = JADE_MALLOC(leaves_len);
    const uint8_t* top_leaves = NULL;
    size_t leaves_written = 0;
    // NOTE: pk_root fingerprint check disabled for testing - keygen makes random
    // keys while signing uses a hardcoded key, so the roots never match.
    // Signatures made with a mismatched cache WILL NOT VERIFY!
    if (0 && storage_get_slh_leaves(is_standard, leaves, leaves_len, &leaves_written)
        && leaves_written == leaves_len
        /* && !memcmp(leaves, sk_bytes + 3 * prm.n, prm.n) */) {
        top_leaves = leaves + prm.n;
        JADE_LOGI("Using cached slh-dsa top-layer leaves");
    } else {
        JADE_LOGI("No matching slh-dsa leaf cache - signing without");
    }

    uint32_t sig_len = slh_sig_sz(&prm);
    sig_output = JADE_MALLOC(sig_len);

    slh_sign(sig_output, (const unsigned char*)message, msg_len, NULL, 0, sk_bytes, NULL, &prm, slh_dsa_progress_adapter, &pb, top_leaves);
    free(leaves);

    jade_process_reply_to_message_bytes(&process->ctx, sig_output, sig_len);
    JADE_LOGI("Success");

cleanup:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (sig_output) free(sig_output);
    if (act) gui_set_current_activity_ex(act, true);
#pragma GCC diagnostic pop
    return;
}
#endif // AMALGAMATED_BUILD