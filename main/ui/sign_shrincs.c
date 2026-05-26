#ifndef AMALGAMATED_BUILD
#include "../ui.h"
#include "../button_events.h"
#include "jade_assert.h"

static gui_activity_t* make_sign_shrincs_activities(const char* msgtxt, gui_activity_t** actmessage1, gui_activity_t** actmessage2)
{
    JADE_ASSERT(msgtxt);
    JADE_INIT_OUT_PPTR(actmessage1);
    JADE_INIT_OUT_PPTR(actmessage2);

    const size_t msgtxt_len = strlen(msgtxt);
    JADE_ASSERT(msgtxt_len <= MAX_DISPLAY_MESSAGE_LEN);

    char buf[MAX_DISPLAY_MESSAGE_LEN + 2];
    const char* message[] = { buf };
    const int ret = snprintf(buf, sizeof(buf), "\n%s", msgtxt);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));

    // Один екран підтвердження: кнопки Reject (=) і Accept (S)
    btn_data_t hdrbtns[] = {
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNMSG_REJECT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT,    .ev_id = BTN_SIGNMSG_ACCEPT } };

    gui_activity_t* const act = make_show_message_activity(message, 1, "Sign", hdrbtns, 2, NULL, 0);

    *actmessage1 = act;
    *actmessage2 = NULL;
    return act;
}

bool show_sign_shrincs_activity(const char* message)
{
    JADE_ASSERT(message);

    gui_activity_t* act_message1 = NULL;
    gui_activity_t* act_message2 = NULL;
    gui_activity_t* act_summary
        = make_sign_shrincs_activities(message, &act_message1, &act_message2);

    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_SIGNMSG_ACCEPT);
        switch (ev_id) {
        case BTN_SIGNMSG_MSG:
            act = act_message1;
            break;

        case BTN_SIGNMSG_NEXT:
            act = (act == act_message1) ? act_message2 : act_summary;
            break;

        case BTN_SIGNMSG_REJECT:
            return false;

        case BTN_SIGNMSG_ACCEPT:
            return true;
        }
    }
}
#endif