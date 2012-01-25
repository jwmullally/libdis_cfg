// test_cfg.c
// Demonstration for cfg.c Control Flow Graph basic block generator for 
// libdisasm.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>
#include <bfd.h>
#include <errno.h>
#include <libdis.h>

#include "cfg.h"



// portable GNU error(3)
void error_exit(int status, int errnum, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (errnum != 0) {
        errno = errnum;
        perror("");
    }
    exit(status);
    return;
}


struct st_insnlist {
    struct st_insnlist *next;
    x86_insn_t *insn;
};



// Disassemble the x86 code contained in 'textbuf'.
// Store the disassembled instructions in a linear array for easy mapping
// of line number to address/offset/instruction
int disassemble_text(unsigned char *textbuf, size_t text_len, uint32_t textaddr, x86_insn_t ***instlist_ptr, int *inst_len)
{
    struct st_insnlist *insnll_head, **insnll_prev_ptr, *insnll_next, *insnll;
    int decode_size, total_read, n_insn, inst_idx;
    x86_insn_t **insnlist;

    // Decode the instructions into a linked list and build the array later.
    insnll_prev_ptr = &insnll_head;
    total_read = 0;
    n_insn = 0;
    while (total_read < text_len ) {
        insnll = malloc(sizeof(struct st_insnlist));
        *(insnll_prev_ptr) = insnll;
        insnll_prev_ptr = &insnll->next;
        insnll->insn = malloc(sizeof(x86_insn_t));
        insnll->next = NULL;
        n_insn++;
        decode_size = x86_disasm(textbuf, text_len, textaddr, total_read, insnll->insn);
        if (decode_size == 0 || (decode_size != 0 && insnll->insn->type == insn_invalid))
            error_exit(-1, 0, "Invalid instruction\n");
        total_read += decode_size;
    }
    insnlist = malloc(n_insn * sizeof(x86_insn_t *));
    insnll = insnll_head;
    inst_idx = 0;
    while (insnll != NULL) {
        insnlist[inst_idx] = insnll->insn;
        insnll_next = insnll->next;
        free(insnll);
        insnll = insnll_next;
        inst_idx++;
    }
    (*instlist_ptr) = insnlist;
    (*inst_len) = n_insn;

    return 0;
}

int print_instructions(x86_insn_t **insts, int insts_len)
{
    char disbuf[1024];
    int inst_idx;
    printf(" Inst#   Offset   Len  Instruction\n");
    for (inst_idx = 0; inst_idx < insts_len; inst_idx++) {
        x86_format_insn(insts[inst_idx], disbuf, 1024, att_syntax);
        printf("%6i : %6x - [%2i] %s\n", inst_idx, insts[inst_idx]->offset, insts[inst_idx]->size, disbuf);
    }
    return 0;
}

   

int main(int argc, char *argv[])
{
    bfd *elf_file;
    asection *text_section;
    int text_len, insts_len, err;
    uint32_t textaddr;
    unsigned char *text;

    x86_insn_t **insts;
    struct cfg_node_list *nodelist, *top_nodes;


    if (argc != 2)
        error_exit(-1, 0, "libdisasm control flow graph example.\n"
                          "Call like: prog [elf-filename]\n");

    bfd_init();
    x86_init(opt_none, 0, 0);


    // Read in the .text section from the ELF executable.
    elf_file = bfd_openr(argv[1], NULL);
    if (elf_file == NULL)
        error_exit(-1, errno, "Unable to open input file '%s':", argv[1]);
    bfd_check_format (elf_file, bfd_object);
    text_section = bfd_get_section_by_name (elf_file, ".text");
    if (text_section == NULL)
        error_exit(-1, 0, "Unable to find .text section in '%s'", argv[1]);
    text_len = bfd_get_section_size(text_section);
    text = malloc(text_len);
    err = bfd_get_section_contents(elf_file, text_section, text, 0, text_len);
    if (err == 0)
        error_exit(-1, 0, "Unable to read .text contents from '%s'", argv[1]);
    textaddr = bfd_get_section_vma(elf_file, text_section);
    
    // Disassemble the text
    printf("Disassembly of '%s':\n\n", argv[1]);
    disassemble_text(text, text_len, textaddr, &insts, &insts_len);
    print_instructions(insts, insts_len);
    printf("\n\n");
    
    // Make the Control Flow Graph from the disassembled instructions.
    cfg_make(insts, insts_len, &nodelist, &top_nodes);

    // Print various CFG graphs
    printf("Control Flow Graph in memory:\n\n");
    cfg_print(nodelist);

    printf("\nDOT graph for CFG:\n\n");
    cfg_fprint_graphviz(stdout, nodelist);

    printf("\nWriting CFG to \'graph.simple.dot'...\n");
    FILE *outfile2 = fopen("graph.simple.dot", "w");
    if (outfile2 == NULL)
        error_exit(-1, errno, "Unable to open 'graph.simple.dot' for writing:");
    cfg_fprint_graphviz(outfile2, nodelist);
    fclose(outfile2);

    printf("Writing CFG to \'graph.dot'...\n\n");
    FILE *outfile3 = fopen("graph.dot", "w");
    if (outfile3 == NULL)
        error_exit(-1, errno, "Unable to open 'graph.simple.dot' for writing:");
    cfg_fprint_graphviz_insts(outfile3, nodelist, insts, insts_len);
    fclose(outfile3);

    cfg_free_list(top_nodes);
    cfg_free_list_and_blocks(nodelist);

    return 0;
}


