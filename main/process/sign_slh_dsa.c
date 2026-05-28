#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"
#include "process_utils.h"
#include "../slh_dsa/slh_dsa.h"
#include "../slh_dsa/slh_param.h"
#include "utils/malloc_ext.h"

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

    const char* message = NULL;
    size_t msg_len = 0;
    rpc_get_string_ptr("message", &params, &message, &msg_len);
    if (msg_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Missing message");
        goto cleanup;
    }

    bool is_standart;
    rpc_get_boolean("is_standart", &params, &is_standart);

    // rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);

    char msg_display[MAX_DISPLAY_MESSAGE_LEN];
    if (msg_len < MAX_DISPLAY_MESSAGE_LEN) {
        snprintf(msg_display, sizeof(msg_display), "%.*s", (int)msg_len, message);
    } else {
        snprintf(msg_display, sizeof(msg_display), "%.*s...", (int)sizeof(msg_display) - 4, message);
    }

    const char* msg_lines[] = { "Sign message?", msg_display };
    if (!await_yesno_activity("SLH-DSA", msg_lines, 2, false, NULL)) {
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined");
        goto cleanup;
    }

    size_t written = 0;

    progress_bar_t pb = {};
    gui_activity_t* act = make_progress_bar_activity("Signing", "Please wait", &pb);
    gui_set_current_activity(act);
    
    slh_param_t prm;
    uint8_t sk_bytes[64];
    int ret;
    if (is_standart)
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

    uint32_t sig_len = slh_sig_sz(&prm); 
    sig_output = JADE_MALLOC(sig_len);

    slh_sign(sig_output, (const unsigned char*)message, msg_len, NULL, 0, sk_bytes, NULL, &prm, slh_dsa_progress_adapter, &pb);

    jade_process_reply_to_message_bytes(&process->ctx, sig_output, sig_len);
    JADE_LOGI("Success");

cleanup:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (sig_output) free(sig_output);
#pragma GCC diagnostic pop
    return;
}
#endif // AMALGAMATED_BUILD