#ifndef __VGA_SWITCH_MODE_H__
#define __VGA_SWITCH_MODE_H__

#include <tboot/printk.h>
#include <opendtex/tss.h>

int init_graph_vga(int width, int height, int chain4);
int set_palette (BYTE * palette);

#endif
