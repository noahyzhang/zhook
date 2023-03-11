#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <sys/mman.h>
#include "common/common.h"
#include "core/elf.h"

namespace zhook {

int ElfManager::hook_impl(std::shared_ptr<LibMapInfo> lib_info) {
    if (elf_init(&(lib_info->elf), lib_info->base_ptr, lib_info->pathname) < 0) {
        ERROR_LOG("ElfManager::hook_impl elf init failed");
        return -1;
    }

}

int ElfManager::elf_init(ElfInfo* elf_info, uintptr_t base_addr, const char* pathname) {
    if (base_addr == 0 || pathname == nullptr) {
        ERROR_LOG("ElfManager::elf_init invalid param");
        return -1;
    }
    elf_info->pathname = pathname;
    elf_info->base_addr = (ElfW(Addr))base_addr;
    elf_info->ehdr = (ElfW(Ehdr)*)base_addr;
    elf_info->phdr = (ElfW(Phdr)*)(base_addr + elf_info->ehdr->e_phoff);

    ElfW(Phdr)* phdr0 = elf_get_first_segment_by_type_offset(elf_info, PT_LOAD, 0);
    if (phdr0 == nullptr) {
        ERROR_LOG("ElfManager::elf_init not found the first load segment, library pathname: %s", pathname);
        return -2;
    }
    // 保存加载的偏移地址
    if (elf_info->base_addr < phdr0->p_vaddr) {
        return -3;
    }
    elf_info->bias_addr = elf_info->base_addr - phdr0->p_vaddr;
    // 寻找 dynamic-segment
    ElfW(Phdr)* dhdr = elf_get_first_segment_by_type(elf_info, PT_DYNAMIC);
    if (dhdr == nullptr) {
        ERROR_LOG("ElfManager::elf_init not found dynamic segment, library pathname: %s", pathname);
        return -4;
    }
    // 解析 dynamic-segment
    elf_info->dyn = (ElfW(Dyn)*)(elf_info->bias_addr + dhdr->p_vaddr);
    elf_info->dyn_sz = dhdr->p_memsz;
    ElfW(Dyn)* dyn = elf_info->dyn;
    ElfW(Dyn)* dyn_end = elf_info->dyn + (elf_info->dyn_sz / sizeof(ElfW(Dyn)));
    uint32_t* raw;
    for (; dyn < dyn_end; dyn++) {
        switch (dyn->d_tag) {
        case DT_NULL:
            dyn = dyn_end;
            break;
        case DT_STRTAB:
            elf_info->strtab = (const char*)(elf_info->bias_addr + dyn->d_un.d_ptr);
            if ((ElfW(Addr))(elf_info->strtab) < elf_info->base_addr) {
                return -5;
            }
            break;
        case DT_SYMTAB:
            elf_info->symtab = (ElfW(Sym)*)(elf_info->bias_addr + dyn->d_un.d_ptr);
            if ((ElfW(Addr))(elf_info->symtab) < elf_info->base_addr) {
                return -6;
            }
            break;
        case DT_PLTREL:
            elf_info->is_use_rela = (dyn->d_un.d_val == DT_RELA ? 1 : 0);
            break;
        case DT_JMPREL:
            elf_info->relplt = (ElfW(Addr))(elf_info->bias_addr + dyn->d_un.d_ptr);
            if ((ElfW(Addr))(elf_info->relplt) < elf_info->base_addr) {
                return -7;
            }
            break;
        case DT_PLTRELSZ:
            elf_info->relplt_sz = dyn->d_un.d_val;
            break;
        case DT_REL:
        case DT_RELA:
            elf_info->reldyn = (ElfW(Addr))(elf_info->bias_addr + dyn->d_un.d_ptr);
            if ((ElfW(Addr))(elf_info->reldyn) < elf_info->base_addr) {
                return -8;
            }
            break;
        case DT_RELSZ:
        case DT_RELASZ:
            elf_info->reldyn_sz = dyn->d_un.d_val;
            break;
        case DT_HASH:
            // 当 elf 文件包含 DT_GNU_HASH 表时，忽略 DT_HASH
            if (elf_info->is_use_gnu_hash) continue;
            raw = (uint32_t*)(elf_info->bias_addr + dyn->d_un.d_ptr);
            if ((ElfW(Addr))raw < elf_info->base_addr) {
                return -9;
            }
            elf_info->bucket_cnt = raw[0];
            elf_info->chain_cnt = raw[1];
            elf_info->bucket = &raw[2];
            elf_info->chain = &(elf_info->bucket[elf_info->bucket_cnt]);
            break;
        case DT_GNU_HASH:
            raw = (uint32_t*)(elf_info->bias_addr + dyn->d_un.d_ptr);
            if ((ElfW(Addr))raw < elf_info->base_addr) {
                return -10;
            }
            elf_info->bucket_cnt = raw[0];
            elf_info->symoffset = raw[1];
            elf_info->bloom_sz = raw[2];
            elf_info->bloom_shift = raw[3];
            elf_info->bloom = (ElfW(Addr)*)(&raw[4]);
            elf_info->bucket = (uint32_t*)(&(elf_info->bloom[elf_info->bloom_sz]));
            elf_info->chain = (uint32_t*)(&(elf_info->bucket[elf_info->bucket_cnt]));
            elf_info->is_use_gnu_hash = 1;
            break;
        default:
            break;
        }
    }

    INFO_LOG("ElfManager::elf_init pathname: %s success, (%s %s PLT:%u DYN:%u)\n",
        elf_info->pathname, elf_info->is_use_rela ? "RELA" : "REL",
        elf_info->is_use_gnu_hash ? "GNU_HASH" : "ELF_HASH",
        elf_info->relplt_sz, elf_info->reldyn_sz);
    return 0;
}

int ElfManager::elf_hook(ElfInfo* elf_info, const char* symbol, void* new_func, void** old_func) {
    if (elf_info->pathname == nullptr) {
        ERROR_LOG("ElfManager::elf_hook pathname is null, not initialized");
        return -1;
    }
    if (symbol == nullptr || new_func == nullptr) {
        ERROR_LOG("ElfManager::elf_hook invalid param");
        return -2;
    }
    INFO_LOG("hooking symbol:%s in library: %s", symbol, elf_info->pathname);
    // 寻找这个符号在 hash 表中的下标
    uint32_t symidx = 0;
    if (elf_find_symidx_by_name(elf_info, symbol, &symidx) < 0) {
        ERROR_LOG("ElfManager::elf_hook not found symbol: %s on library: %s", symbol, elf_info->pathname);
        return 0;
    }
    int found;
    // 替换 .rel(a).plt
    if (elf_info->relplt != 0) {
        uint8_t* cur = (uint8_t*)elf_info->relplt;
        uint8_t* end = cur + elf_info->relplt_sz;
        size_t step = elf_info->is_use_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
        for (; cur < end; cur += step) {
            int res = elf_find_and_replace_symbol(elf_info,
                (elf_info->is_use_rela ? ".rela.plt" : ".rel.plt"),
                1, symbol, new_func, old_func, symidx, cur, &found);
            if (res < 0) {
                return res;
            }
            if (found) break;
        }
    }
    // 替换 .rel(a).dyn
    if (elf_info->reldyn != 0) {
        uint8_t* cur = (uint8_t*)elf_info->reldyn;
        uint8_t* end = cur + elf_info->reldyn_sz;
        size_t step = elf_info->is_use_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
        for (; cur < end; cur += step) {
            int res = elf_find_and_replace_symbol(elf_info,
                (elf_info->is_use_rela ? ".rela.dyn" : ".rel.dyn"),
                0, symbol, new_func, old_func, symidx, cur, nullptr);
            if (res < 0) {
                return res;
            }
        }
    }
    return 0;
}

int ElfManager::elf_find_and_replace_symbol(ElfInfo* elf_info, const char* section, int is_plt,
    const char* symbol, void* new_func, void** old_func, uint32_t symidx, void* rel_common, int* found) {
    if (found) {
        found = 0;
    }
    size_t r_info;
    ElfW(Addr) r_offset;
    if (elf_info->is_use_rela) {
        ElfW(Rela)* rela = (ElfW(Rela)*)rel_common;
        r_info = rela->r_info;
        r_offset = rela->r_offset;
    } else {
        ElfW(Rel)* rel = (ElfW(Rel)*)rel_common;
        r_info = rel->r_info;
        r_offset = rel->r_offset;
    }
    // 检查 sym
    size_t r_sym = XH_ELF_R_SYM(r_info);
    if (r_sym != symidx) {
        return 0;
    }
    // 检查 type
    size_t r_type = XH_ELF_R_TYPE(r_info);
    if (is_plt && r_type != XH_ELF_R_GENERIC_JUMP_SLOT) {
        return 0;
    }
    if (!is_plt && (r_type != XH_ELF_R_GENERIC_GLOB_DAT && r_type != XH_ELF_R_GENERIC_ABS)) {
        return 0;
    }
    INFO_LOG("found %s as %s offset: %p", symbol, section, (void*)r_offset);
    if (found != nullptr) {
        *found = 1;
    }
    // 可以去替换了
    ElfW(Addr) addr = elf_info->bias_addr + r_offset;
    if (addr < elf_info->base_addr) {
        return -1;
    }
    int res = elf_replace_symbol(elf_info, symbol, addr, new_func, old_func);
    if (res < 0) {
        ERROR_LOG("ElfManager::elf_find_and_replace_symbol replace symbol: %s at section: %s failed", symbol, section);
        return res;
    }
    return 0;
}

int ElfManager::elf_replace_symbol(ElfInfo* elf_info,
    const char* symbol, ElfW(Addr) addr, void* new_func, void** old_func) {
    if (*(void**)addr == new_func) {
        return 0;
    }
    unsigned int old_prot = 0;
    unsigned int need_prot = PROT_READ | PROT_WRITE;
    // 获取旧的 prot 标识
    int res = get_mem_addr_protect(addr, sizeof(addr), elf_info->pathname, &old_prot);
    if (res < 0) {
        ERROR_LOG("ElfManager::elf_replace_symbol get mem addr prot failed, res: %d", res);
        return res;
    }
    if (old_prot != need_prot) {
        res = set_mem_addr_protect(addr, need_prot);
        if (res < 0) {
            ERROR_LOG("ElfManager::elf_replace_symbol set mem addr rw prot failed, res: %s", res);
            return res;
        }
    }
    // 保存旧的函数
    void* old_addr = *(void**)addr;
    if (old_func) {
        *old_func = old_addr;
    }
    // 替换新函数
    *(void**)addr = new_func;
    if (old_prot != need_prot) {
        // 重置旧的保护类型
        res = set_mem_addr_protect(addr, old_prot);
        if (res < 0) {
            WARN_LOG("ElfManager::elf_replace_symbol restore mem addr prot failed, res: %d", res);
        }
    }
    // 清理缓存

    INFO_LOG("replace symbol success, addr: %p, old addr: %p -> new addr: %p, symbol: %s at pathname: %s",
        (void*)addr, old_addr, new_func, symbol, elf_info->pathname);
    return 0;
}

ElfW(Phdr)* ElfManager::elf_get_first_segment_by_type(ElfInfo* elf_info, ElfW(Word) type) {
    ElfW(Phdr)* phdr = elf_info->phdr;
    for (; phdr < elf_info->phdr + elf_info->ehdr->e_phnum; phdr++) {
        if (phdr->p_type == type) {
            return phdr;
        }
    }
    return nullptr;
}

ElfW(Phdr)* ElfManager::elf_get_first_segment_by_type_offset(ElfInfo* elf_info, ElfW(Word) type, ElfW(Off) offset) {
    ElfW(Phdr)* phdr = elf_info->phdr;
    for (; phdr < elf_info->phdr + elf_info->ehdr->e_phnum; phdr++) {
        if (phdr->p_type == type && phdr->p_offset == offset) {
            return phdr;
        }
    }
    return nullptr;
}

int ElfManager::elf_find_symidx_by_name(ElfInfo* elf_info, const char* symbol, uint32_t* symidx) {
    if (elf_info->is_use_gnu_hash) {
        return elf_lookup_gnu_hash(elf_info, symbol, symidx);
    } else {
        return elf_lookup_hash(elf_info, symbol, symidx);
    }
}

int ElfManager::elf_lookup_gnu_hash(ElfInfo* elf_info, const char* symbol, uint32_t* symidx) {
    if (0 == elf_gnu_hash_lookup_def(elf_info, symbol, symidx)) return 0;
    if (0 == elf_gnu_hash_lookup_undef(elf_info, symbol, symidx)) return 0;
    return -1;
}

int ElfManager::elf_lookup_hash(ElfInfo* elf_info, const char* symbol, uint32_t* symidx) {
    uint32_t hash = elf_hash((uint8_t*)symbol);
    uint32_t i = elf_info->bucket[hash & elf_info->bucket_cnt];
    const char* symbol_cur;
    for (; i != 0; i = elf_info->chain[i]) {
        symbol_cur = elf_info->strtab + elf_info->symtab[i].st_name;
        if (strcmp(symbol, symbol_cur) == 0) {
            *symidx = 1;
            INFO_LOG("ElfManager::elf_lookup_hash found symbol: %s at symidx: %u (ELF_HASH)", symbol, *symidx);
            return 0;
        }
    }
    return -1;
}

int ElfManager::get_mem_addr_protect(uintptr_t addr, size_t len, const char* pathname, unsigned int* prot) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        ERROR_LOG("ElfManager::get_mem_addr_protect call fopen failed, err: %s", strerror(errno));
        return -1;
    }
    char line[512];
    uintptr_t start, end;
    char perm[5];
    uintptr_t start_addr = addr;
    uintptr_t end_addr = addr + len;
    bool first_load = true;
    bool found_all = false;
    for (; fgets(line, sizeof(line), fp);) {
        if (pathname != nullptr) {
            if (strstr(line, pathname) == nullptr) continue;
        }
        if (sscanf(line, "%"PRIxPTR"-%"PRIxPTR" %4s ", &start, &end, perm) != 3) continue;
        if (perm[3] != 'p') continue;
        if (start_addr >= start && start_addr < end) {
            if (first_load) {
                // 第一次加载到这个段
                if (perm[0] == 'r') *prot |= PROT_READ;
                if (perm[1] == 'w') *prot |= PROT_WRITE;
                if (perm[2] == 'x') *prot |= PROT_EXEC;
                first_load = false;
            } else {
                if (perm[0] != 'r') *prot &= ~PROT_READ;
                if (perm[1] != 'w') *prot &= ~PROT_WRITE;
                if (perm[2] != 'x') *prot &= ~PROT_EXEC;
            }
            if (end_addr <= end) {
                found_all = true;
                break;
            } else {
                // 尝试去寻找下一个加载的段
                start_addr = end;
            }
        }
    }
    fclose(fp);
    if (!found_all) return -2;
    return 0;
}

int ElfManager::set_mem_addr_protect(uintptr_t addr, unsigned int prot) {
    if (mprotect((void*)PAGE_START(addr), PAGE_COVER(addr), (int)prot) != 0) {
        ERROR_LOG("ElfManager::set_mem_addr_protect call mprotect failed, err: %s", strerror(errno));
        return -1;
    }
    return 0;
}

uint32_t ElfManager::elf_hash(const uint8_t* name) {
    uint32_t h = 0, g;
    for (; *name;) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

uint32_t ElfManager::elf_gnu_hash(const uint8_t* name) {
    uint32_t h = 5381;
    for (; *name != 0;) {
        h += (h << 5) + *name++;
    }
    return h;
}

int ElfManager::elf_gnu_hash_lookup_def(ElfInfo* elf_info, const char* symbol, uint32_t* symidx) {
    uint32_t hash = elf_gnu_hash((uint8_t*)symbol);
    static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
    size_t word = elf_info->bloom[(hash / elfclass_bits) % elf_info->bloom_sz];
    size_t mask = 0 | ((size_t)1 << (hash % elfclass_bits))
        | ((size_t)1 << ((hash >> elf_info->bloom_shift) % elfclass_bits));
    if ((word & mask) != mask) return -1;
    uint32_t index = elf_info->bucket[hash % elf_info->bucket_cnt];
    if (index < elf_info->symoffset) return -2;
    for (;;) {
        const char* symname = elf_info->strtab + elf_info->symtab[index].st_name;
        const uint32_t symhash = elf_info->chain[index - elf_info->symoffset];
        if ((hash | (uint32_t)1) == (symhash | (uint32_t)1) && 0 == strcmp(symbol, symname)) {
            *symidx = index;
            INFO_LOG("found symbol: %s at symidx: %u (GNU_HASH DEF)", symbol, *symidx);
            return 0;
        }
        if (symhash & (uint32_t)1) break;
        index++;
    }
    return -3;
}

int ElfManager::elf_gnu_hash_lookup_undef(ElfInfo* elf_info, const char* symbol, uint32_t* symidx) {
    for (size_t i = 0; i < elf_info->symoffset; ++i) {
        const char* symname = elf_info->strtab + elf_info->symtab[i].st_name;
        if (0 == strcmp(symname, symbol)) {
            *symidx = i;
            INFO_LOG("found symbol: %s at symidx: %u (GNU_HASH UNDEF)", symbol, *symidx);
            return 0;
        }
    }
    return -1;
}

int ElfManager::read_process_maps() {
    uintptr_t base_addr = 0;
    uintptr_t prev_base_addr = 0;
    char perm[5] = {0};
    char prev_perm[5] = "---p";
    uint64_t offset = 0;
    uint64_t prev_offset = 0;
    uint64_t pathname_pos = 0;
    char* pathname = nullptr;
    char prev_pathname[512] = {0};
    size_t pathname_len = 0;

    // 读取 maps 的每一行
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        ERROR_LOG("ElfManager::read_process_maps fopen /proc/self/maps failed, err: %s", strerror(errno));
        return -1;
    }
    char line[512] = {0};
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%"PRIxPTR"-%*lx %4s %lx %*x:%*x %*d%n", &base_addr, perm, &offset, &pathname_pos) != 3) {
            continue;
        }
        // 只保存私有的库
        if (perm[3] != 'p') {
            continue;
        }
        // 过滤掉权限为空的库
        if (perm[0] == '-' && perm[1] == '-' && perm[2] == '-') {
            continue;
        }
        // 获取库的路径名
        while (isspace(line[pathname_pos]) && pathname_pos < (sizeof(line) - 1)) {
            pathname_pos++;
        }
        if (pathname_pos >= (sizeof(line)-1)) continue;
        pathname = line + pathname_pos;
        pathname_len = strlen(pathname);
        if (0 == pathname_len) continue;
        // 注意库的路径名尾部有换行符
        if (pathname[pathname_len - 1] == '\n') {
            pathname[pathname_len - 1] = '\0';
            pathname_len--;
        }
        if (0 == pathname_len) continue;
        if ('[' == pathname[0]) continue;
        // 对于没有执行权限的库，需要记录，因为 so maps 可以从一个没有权限的库开始
        if (perm[2] != 'x') {
            prev_offset = offset;
            prev_base_addr = base_addr;
            memcpy(prev_perm, perm, sizeof(prev_perm));
            strncpy(prev_pathname, pathname, pathname_len);
            continue;
        }
        // 对于拥有执行权限的库，如果 offset 为 0，则是我们想要找的
        // 或者如果 offset 不为 0, 那我们需要检查之前的记录的那个库
        if (offset != 0) {
            if (strcmp(prev_pathname, pathname) || prev_offset != 0 || prev_perm[0] != 'r') {
                continue;
            }
            base_addr = prev_base_addr;
        }
        

    }
}

}  // namespace zhook
