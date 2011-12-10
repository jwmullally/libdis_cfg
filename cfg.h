// cfg.h
// A Control Flow Graph basic block generator for use with the 
// libdisasm x86 disassembler, written in C.
// Joe Mullally 2011, released into the Public Domain.

#ifndef __CFG_H__
#define __CFG_H__

// Need to include libdis.h for the x86_insn_t use below. People will need to includes this anyway.
#include <libdis.h>

struct cfg_node {
    struct cfg_node_list *parents;
    int start_inst;
    int block_len;
    struct cfg_node_list *children;
};

struct cfg_node_list {
    struct cfg_node *node;
    struct cfg_node_list *next;
};

// Make a basic control flow graph for the inputted text
// This is a simple linear sweep.
void cfg_make(x86_insn_t **insts, int insts_len, struct cfg_node_list **nodelist_ret, struct cfg_node_list **top_nodes_ret);
// Free the CFG node lists returned from cfg_make().
void cfg_free(struct cfg_node_list *node_list);
// Simple CFG output suitable for debugging.
void cfg_print(struct cfg_node_list *node_list);
// Output the complete CFG node list as a graphviz graph.
// Render with: dot -Tps output.dot -o output.ps
void cfg_fprint_graphviz(FILE *outfile, struct cfg_node_list *node_list);
// Output the complete CFG node list as a graphviz graph.
// Render with: dot -Tps output.dot -o output.ps
// Label the graph nodes with the disassembled instructions.
void cfg_fprint_graphviz_insts(FILE *outfile, struct cfg_node_list *node_list, x86_insn_t **insts, int insts_len);

#endif // __CFG_H__
