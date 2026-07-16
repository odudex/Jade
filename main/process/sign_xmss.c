#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"
#include "process_utils.h"
#include "../xmss/xmss_core.h"
// #include "../storage.h"
#include "utils/malloc_ext.h"
#include <mbedtls/sha512.h>

static void xmss_progress_adapter(uint32_t current, uint32_t total, void* userdata)
{
    progress_bar_t* pb = (progress_bar_t*)userdata;
    update_progress_bar(pb, total, current);
}

void xmss_key_gen_process(void* process_ptr)
{
    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "xmss_key_gen");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    gui_activity_t* act = NULL;
    progress_bar_t pb = {};
    uint8_t *sk = NULL, *pk = NULL;

    uint8_t bytes[32];
    size_t bytes_len = 0;
    rpc_get_bytes("bytes", 32, &params, bytes, &bytes_len);
    if (bytes_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Expected 32-byte seed");
        goto cleanup;
    }

    uint8_t sha512_out[64];
    mbedtls_sha512(bytes, 32, sha512_out, 0);
    
    uint32_t oid = 0x000000ff;

    xmss_params xparams;
    if (xmss_parse_oid(&xparams, oid) != 0) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Invalid XMSS OID");
        goto cleanup;
    }

    act = make_progress_bar_activity("Keygen", "Please wait", &pb);
    gui_set_current_activity(act);

    // sk: OID(4) + index_bytes + SK_SEED + SK_PRF + root + PUB_SEED
    // pk: OID(4) + root + PUB_SEED
    size_t sk_total = XMSS_OID_LEN + (size_t)xparams.sk_bytes;
    size_t pk_total = XMSS_OID_LEN + (size_t)xparams.pk_bytes;

    sk = JADE_MALLOC(sk_total);
    pk = JADE_MALLOC(pk_total);

    for (unsigned int i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }

    xmssmt_core_seed_keypair(&xparams, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN,
                             sha512_out,
                             xmss_progress_adapter, &pb);

    jade_process_reply_to_message_bytes(&process->ctx, sk, sk_total);

cleanup:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (sk) free(sk);
    if (pk) free(pk);
    if (act) gui_set_current_activity_ex(act, true);
#pragma GCC diagnostic pop
    return;
}

void sign_xmss_process(void* process_ptr)
{
    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "sign_xmss");
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

    // rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);

    // char msg_display[MAX_DISPLAY_MESSAGE_LEN];
    // if (msg_len < MAX_DISPLAY_MESSAGE_LEN) {
    //     snprintf(msg_display, sizeof(msg_display), "%.*s", (int)msg_len, message);
    // } else {
    //     snprintf(msg_display, sizeof(msg_display), "%.*s...", (int)sizeof(msg_display) - 4, message);
    // }

    // const char* msg_lines[] = { "Sign message?", msg_display };
    // if (!await_yesno_activity("SLH-DSA", msg_lines, 2, false, NULL)) {
    //     jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined");
    //     goto cleanup;
    // }

    size_t written = 0;
    uint8_t sk_bytes[72];
    int ret = wally_hex_to_bytes("000000ff00000000b809496f05c121c581b0c7d570a9f7212230654732ee37386867f889755ce3dc2eee098dfb7b52a4042220ab6ff8a702829765a3d900a6359204ef3d352c6023", sk_bytes, sizeof(sk_bytes), &written);

    if (ret != WALLY_OK || written != 72) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Sign failed");
        goto cleanup;
    }

    act = make_progress_bar_activity("Signing", "Please wait", &pb);
    gui_set_current_activity(act);

    uint32_t oid = 0;
    for (int i = 0; i < XMSS_OID_LEN; i++) {
        oid |= (uint32_t)sk_bytes[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    xmss_params xparams;
    if (xmss_parse_oid(&xparams, oid) != 0) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Invalid OID in secret key");
        goto cleanup;
    }

    size_t sm_max = (size_t)xparams.sig_bytes + msg_len;
    unsigned long long smlen = 0;
    sig_output = JADE_MALLOC(sm_max);

    ret = xmss_core_sign(&xparams, sk_bytes + XMSS_OID_LEN, sig_output, &smlen,
                         message, msg_len,
                         xmss_progress_adapter, &pb);
    if (ret != 0) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Sign failed");
        goto cleanup;
    }

    jade_process_reply_to_message_bytes(&process->ctx, sig_output, xparams.sig_bytes);
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