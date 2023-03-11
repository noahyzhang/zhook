/**
 * @file elf.h
 * @author noahyzhang
 * @brief 
 * @version 0.1
 * @date 2023-03-11
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#pragma once

#include <map>
#include <memory>
#include "core/stu.h"

namespace zhook {

#if defined(__arm__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#define XH_ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#define XH_ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_386_32
#elif defined(__x86_64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_X86_64_64
#endif

#if defined(__LP64__)
#define XH_ELF_R_SYM(info)  ELF64_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define XH_ELF_R_SYM(info)  ELF32_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

class ElfManager {
private:
    int hook_impl(std::shared_ptr<LibMapInfo> lib_info);
    int elf_init(ElfInfo* elf_info, uintptr_t base_addr, const char* pathname);
    int elf_hook(ElfInfo* elf_info, const char* symbol, void* new_func, void** old_func);

private:
    ElfW(Phdr)* elf_get_first_segment_by_type(ElfInfo* elf_info, ElfW(Word) type);
    ElfW(Phdr)* elf_get_first_segment_by_type_offset(ElfInfo* elf_info, ElfW(Word) type, ElfW(Off) offset);

    int elf_find_and_replace_symbol(ElfInfo* elf_info, const char* section, int is_plt,
        const char* symbol, void* new_func, void** old_func, uint32_t symidx, void* rel_common, int* found);
    int elf_replace_symbol(ElfInfo* elf_info, const char* symbol, ElfW(Addr) addr, void* new_func, void** old_func);

    int elf_find_symidx_by_name(ElfInfo* elf_info, const char* symbol, uint32_t* symidx);
    int elf_lookup_gnu_hash(ElfInfo* elf_info, const char* symbol, uint32_t* symidx);
    int elf_lookup_hash(ElfInfo* elf_info, const char* symbol, uint32_t* symidx);

private:
    int get_mem_addr_protect(uintptr_t addr, size_t len, const char* pathname, unsigned int* prot);
    int set_mem_addr_protect(uintptr_t addr, unsigned int prot);

private:
    static uint32_t elf_hash(const uint8_t* name);
    static uint32_t elf_gnu_hash(const uint8_t* name);
    static int elf_gnu_hash_lookup_def(ElfInfo* elf_info, const char* symbol, uint32_t* symidx);
    static int elf_gnu_hash_lookup_undef(ElfInfo* elf_info, const char* symbol, uint32_t* symidx);
    int read_process_maps();

private:

};

}  // namespace zhook
