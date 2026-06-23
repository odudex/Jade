#ifndef AMALGAMATED_BUILD
#include "../ui.h"
#include "jade_assert.h"
#include "sdkconfig.h"
#include <string.h>

extern const uint8_t shrinsc_start[] asm("_binary_shrincs_bin_gz_start");
extern const uint8_t shrinsc_end[]   asm("_binary_shrincs_bin_gz_end");

#define DOT_SLOT_PX (CONFIG_DISPLAY_WIDTH / SHRINCS_TRACK_LEN)

static void shrincs_render(shrincs_progress_t* sp, uint8_t pos)
{
    JADE_ASSERT(sp);
    JADE_ASSERT(pos < SHRINCS_TRACK_LEN);

    if (pos == sp->last_pos) {
        return;
    }

    sp->shrimp_slots[sp->last_pos]->picture->picture = NULL;

    for (uint8_t i = sp->last_pos; i <= pos && i < SHRINCS_TRACK_LEN; ++i) {
        gui_update_text(sp->food[i], " ");
        gui_repaint(sp->slots[i]);
    }

    gui_update_picture(sp->shrimp_slots[pos], sp->shrimp_pic, true);
}

gui_activity_t* make_shrincs_progress_activity(const char* title, const char* message, shrincs_progress_t* sp)
{
    JADE_ASSERT(title);
    JADE_ASSERT(message);
    JADE_ASSERT(sp);

    memset(sp, 0, sizeof(shrincs_progress_t));

    sp->shrimp_pic = get_picture(shrinsc_start, shrinsc_end);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 30, 40, 30);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* msgnode;
    gui_make_text(&msgnode, message, TFT_WHITE);
    gui_set_align(msgnode, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(msgnode, vsplit);

    gui_view_node_t* row_bg;
    gui_make_fill(&row_bg, TFT_BLACK, FILL_PLAIN, NULL);
    gui_set_parent(row_bg, vsplit);

    gui_view_node_t* row;
    gui_make_hsplit(&row, GUI_SPLIT_ABSOLUTE, SHRINCS_TRACK_LEN,
        DOT_SLOT_PX, DOT_SLOT_PX, DOT_SLOT_PX, DOT_SLOT_PX, DOT_SLOT_PX,
        DOT_SLOT_PX, DOT_SLOT_PX, DOT_SLOT_PX, DOT_SLOT_PX, DOT_SLOT_PX);
    gui_set_parent(row, row_bg);

    for (uint8_t i = 0; i < SHRINCS_TRACK_LEN; ++i) {
        gui_make_fill(&sp->slots[i], TFT_BLACK, FILL_PLAIN, NULL);
        gui_set_parent(sp->slots[i], row);

        gui_make_picture(&sp->shrimp_slots[i], NULL);
        gui_set_align(sp->shrimp_slots[i], GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(sp->shrimp_slots[i], sp->slots[i]);

        gui_make_text(&sp->food[i], ".", TFT_WHITE);
        gui_set_align(sp->food[i], GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(sp->food[i], sp->shrimp_slots[i]);
    }

    gui_view_node_t* pcnt_bg;
    gui_make_fill(&pcnt_bg, TFT_BLACK, FILL_PLAIN, NULL);
    gui_set_parent(pcnt_bg, vsplit);
    gui_make_text(&sp->pcnt, "0%", TFT_WHITE);
    gui_set_align(sp->pcnt, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(sp->pcnt, pcnt_bg);

    gui_update_picture(sp->shrimp_slots[0], sp->shrimp_pic, true);
    gui_update_text(sp->food[0], " ");

    sp->last_pos = 0;
    return act;
}

void update_shrincs_progress(shrincs_progress_t* sp, size_t total, size_t current)
{
    JADE_ASSERT(sp);
    JADE_ASSERT(total > 0);
    if (current > total) {
        current = total;
    }

    char txt[8];
    snprintf(txt, sizeof(txt), "%u%%", (unsigned)(100 * current / total));
    gui_update_text(sp->pcnt, txt);

    const uint8_t pos = (uint8_t)((SHRINCS_TRACK_LEN - 1) * current / total);
    shrincs_render(sp, pos);
    sp->last_pos = pos;
}

void free_shrincs_progress(shrincs_progress_t* sp)
{
    JADE_ASSERT(sp);
    if (sp->shrimp_pic) {
        for (uint8_t i = 0; i < SHRINCS_TRACK_LEN; ++i) {
            if (sp->shrimp_slots[i]) {
                sp->shrimp_slots[i]->picture->picture = NULL;
            }
        }
        if (sp->shrimp_pic->data_8) {
            free((void*)sp->shrimp_pic->data_8);
        }
        free(sp->shrimp_pic);
        sp->shrimp_pic = NULL;
    }
}
#endif