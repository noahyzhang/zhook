/**
 * @file common.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-11
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#pragma once

#include <string>
#include <elf.h>
#include <link.h>

namespace zhook {

struct ElfInfo {
    const char* pathname;

    ElfW(Addr)  base_addr;
    ElfW(Addr)  bias_addr;

    // ELF 文件头
    ElfW(Ehdr) *ehdr;
    // ELF 程序头表，用来标村 segment 的信息
    ElfW(Phdr) *phdr;

    // .dynamic 
    ElfW(Dyn)  *dyn;
    ElfW(Word)  dyn_sz;

    // .dynstr (string-table)
    const char *strtab;
    // .dynsym (symbol-index to string-table's offset)
    ElfW(Sym)  *symtab;

    // .rel.plt or .rela.plt
    ElfW(Addr)  relplt;
    ElfW(Word)  relplt_sz;

    // .rel.dyn or .rela.dyn
    ElfW(Addr)  reldyn;
    ElfW(Word)  reldyn_sz;

    // android compressed rel or rela
    ElfW(Addr)  relandroid;
    ElfW(Word)  relandroid_sz;

    // for ELF hash
    uint32_t   *bucket;
    uint32_t    bucket_cnt;
    uint32_t   *chain;
    // invalid for GNU hash
    uint32_t    chain_cnt;

    // append for GNU hash
    uint32_t    symoffset;
    ElfW(Addr) *bloom;
    uint32_t    bloom_sz;
    uint32_t    bloom_shift;

    int         is_use_rela;
    int         is_use_gnu_hash;
};

struct LibMapInfo {
    const char* pathname;
    uintptr_t base_ptr;
    ElfInfo elf;
};

}  // namespace zhook
