#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"
#include "process_utils.h"
#include "../shrincs/shrincs.h"
#include "utils/malloc_ext.h"

bool show_sign_shrincs_activity(const char* message);

static void jade_progress_adapter(uint16_t current, void* userdata)
{
    shrincs_progress_t* sp = (shrincs_progress_t*)userdata;
    update_shrincs_progress(sp, 1000, current);
}

void sign_shrincs_process(void* process_ptr)
{
    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "sign_shrincs");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    uint8_t* sig_output = NULL;
    gui_activity_t* act = NULL;
    shrincs_progress_t shrincs = {};

    uint8_t message[32];
    size_t msg_len = 0;
    // rpc_get_string_ptr("message", &params, &message, &msg_len);
    rpc_get_bytes("message", 32, &params, message, &msg_len);
    if (msg_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Missing message");
        goto cleanup;
    }

    uint64_t swn;
    rpc_get_uint64_t("swn", &params, &swn);

    // rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);

    char msg_display[MAX_DISPLAY_MESSAGE_LEN];
    if (msg_len < MAX_DISPLAY_MESSAGE_LEN) {
        snprintf(msg_display, sizeof(msg_display), "%.*s", (int)msg_len, message);
    } else {
        snprintf(msg_display, sizeof(msg_display), "%.*s...", (int)sizeof(msg_display) - 4, message);
    }

    if (!show_sign_shrincs_activity(msg_display)) {
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined");
        goto cleanup;
    }

    size_t written = 0;

    act = make_shrincs_progress_activity("Signing", "Please wait", &shrincs);
    gui_set_current_activity(act);

    uint8_t sk_bytes[96];
    int ret = wally_hex_to_bytes("0517400a7d4f5a532d4f34b077182caf1a79e406404e29a7feed94aa546330ac00ae2c282f33b319d83b705b4b5487c618311f77a5283cf39aabaf35dc3dfd79918fd17d889f34eb76a99a0c93a2015eda5a08dc47d1e05d0d4d816f72e78e27", sk_bytes, sizeof(sk_bytes), &written);

    if (ret != WALLY_OK || written != 96) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Sign failed");
        goto cleanup;
    }

    State state;
    state.q = 0;
    state.valid = 1;

    const size_t sig_len = N + WOTS_SIGN_LEN + (state.q + 1) * N;

    SecretKey sk;
    memcpy(sk.seed,     sk_bytes,         N);
    memcpy(sk.prf,      sk_bytes + N,     N);
    memcpy(sk.sf,       sk_bytes + N * 2, N);
    memcpy(sk.sl,       sk_bytes + N * 3, N);
    memcpy(sk.pk.seed,  sk_bytes + N * 4, N);
    memcpy(sk.pk.root,  sk_bytes + N * 5, N);

    sig_output = JADE_MALLOC(sig_len);

    if (!shrincs_sign_stateful((const uint8_t*)message, msg_len, &sk, &state, swn, sig_output, jade_progress_adapter, &shrincs)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Sign failed");
        goto cleanup;
    }

    jade_process_reply_to_message_bytes(&process->ctx, sig_output, sig_len);
    JADE_LOGI("Success");

cleanup:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (sig_output) free(sig_output);
    free_shrincs_progress(&shrincs);
    if (act) gui_set_current_activity_ex(act, true);
#pragma GCC diagnostic pop
    return;
}
#endif // AMALGAMATED_BUILD