#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common.h"
#include "elf_manager.h"

namespace zhook {

ELFManager::~ELFManager() {
    if (fd_ > 0) {
        close(fd_);
    }
}

int ELFManager::get_elf_symtab(std::shared_ptr<std::vector<Elf_SymbolSection>> symtab) {
    return read_elf_symbol_section(symtab, SHT_SYMTAB);
}

int ELFManager::read_elf_symbol_section(
    std::shared_ptr<std::vector<Elf_SymbolSection>> symbol_table, unsigned int type) {
    // 寻找相关 type 的段
    size_t i = 0;
    for (; i < ehdr_.e_shnum; ++i) {
        if (shdrs_[i].sh_type == type) {
            break;
        }
    }
    if (i == ehdr_.e_shnum) {
        ERROR_LOG("get_elf_symbol_section of not found type: %d", type);
        return -1;
    }
    // 拿到 symbol 段
    Elf_Shdr* sym_section = &shdrs_[i];
    // 获取到字符串表
    Elf_Shdr* link = &shdrs_[sym_section->sh_link];
    char* sym_names = reinterpret_cast<char*>(malloc(link->sh_size));
    if (sym_names == nullptr) {
        ERROR_LOG("get_elf_symbol_section of malloc failed, err: %s", strerror(errno));
        return -2;
    }
    int res = read_elf(link->sh_offset, sym_names, link->sh_size);
    if (res < 0) {
        return -3;
    }
    // 段的长度 / 项的长度（对于符号表，每个符号就是一项）
    int count = sym_section->sh_size / sym_section->sh_entsize;
    symbol_table->resize(count);
    // 提取出符号表中的每个符号
    if (is_32_bit_) {
        Elf32_Sym syms[count];
        res = read_elf(sym_section->sh_offset, syms, sym_section->sh_size);
        if (res < 0) {
            return -4;
        }
        for (size_t i = 0; i < count; ++i) {
            (*symbol_table)[i].name = &sym_names[syms[i].st_name];
            (*symbol_table)[i].bind = ELF32_ST_BIND(syms[i].st_info);
            (*symbol_table)[i].type = ELF32_ST_TYPE(syms[i].st_info);
            (*symbol_table)[i].shndx = syms[i].st_shndx;
            (*symbol_table)[i].value = syms[i].st_value;
            (*symbol_table)[i].size = syms[i].st_size;
        }
    } else {
        Elf64_Sym syms[count];
        res = read_elf(sym_section->sh_offset, syms, sym_section->sh_size);
        if (res < 0) {
            return -5;
        }
        for (size_t i = 0; i < count; ++i) {
            (*symbol_table)[i].name = &sym_names[syms[i].st_name];
            (*symbol_table)[i].bind = ELF64_ST_BIND(syms[i].st_info);
            (*symbol_table)[i].type = ELF64_ST_TYPE(syms[i].st_info);
            (*symbol_table)[i].shndx = syms[i].st_shndx;
            (*symbol_table)[i].value = syms[i].st_value;
            (*symbol_table)[i].size = syms[i].st_size;
        }
    }
    return count;
}

int ELFManager::read_elf_relsym_section(
    std::shared_ptr<std::vector<Elf_RealSymbolSection>> rel_table, unsigned max_count) {
    int count = 0;
    int res;
    for (size_t i = 0; i < ehdr_.e_shnum; ++i) {
        if (shdrs_[i].sh_type == SHT_REL || shdrs_[i].sh_type == SHT_RELA) {
            char* rel = reinterpret_cast<char*>(malloc(shdrs_[i].sh_size));
            if (rel == nullptr) {
                ERROR_LOG("get_elf_relsym_section of malloc failed, err: %s", strerror(errno));
                return -1;
            }
            int num = shdrs_[i].sh_size / shdrs_[i].sh_entsize;
            count += num;
            res = read_elf(shdrs_[i].sh_offset, rel, shdrs_[i].sh_size);
            if (res < 0) {
                return -2;
            }
            if (is_32_bit_) {
                if (shdrs_[i].sh_type == SHT_REL) {
                    Elf32_Rel* prel = reinterpret_cast<Elf32_Rel*>(rel);
                    for (size_t i = 0; i < num; ++i) {
                        (*rel_table)[i].offset = prel[i].r_offset;
                        (*rel_table)[i].type = ELF32_R_TYPE(prel[i].r_info);
                        (*rel_table)[i].symid = ELF32_R_SYM(prel[i].r_info);
                    }
                } else {
                    Elf32_Rela* prel = reinterpret_cast<Elf32_Rela*>(rel);
                    for (size_t i = 0; i < num; ++i) {
                        (*rel_table)[i].offset = prel[i].r_offset;
                        (*rel_table)[i].type = ELF32_R_TYPE(prel[i].r_info);
                        (*rel_table)[i].symid = ELF32_R_SYM(prel[i].r_info);
                    }
                }
            } else {
                if (shdrs_[i].sh_type == SHT_REL) {
                    Elf64_Rel* prel = reinterpret_cast<Elf64_Rel*>(rel);
                    for (size_t i = 0; i < num; ++i) {
                        (*rel_table)[i].offset = prel[i].r_offset;
                        (*rel_table)[i].type = ELF64_R_TYPE(prel[i].r_info);
                        (*rel_table)[i].symid = ELF64_R_SYM(prel[i].r_info);
                    }
                } else {
                    Elf64_Rela* prel = reinterpret_cast<Elf64_Rela*>(rel);
                    for (size_t i = 0; i < num; ++i) {
                        (*rel_table)[i].offset = prel[i].r_offset;
                        (*rel_table)[i].type = ELF64_R_TYPE(prel[i].r_info);
                        (*rel_table)[i].symid = ELF64_R_SYM(prel[i].r_info);
                    }
                }
            }
            if (rel) {
                free(rel);
            }
        }
    }
    return count;
}

int ELFManager::init(const char* file_name) {
    fd_ = open(file_name, O_RDONLY);
    if (fd_ < 0) {
        ERROR_LOG("init of open failed, err: %s", strerror(errno));
        return -1;
    }
    // 读取 elf header 的 ident，用来判断操作系统位数
    int res = read_elf(0, ident_, sizeof(ident_));
    if (res < 0) {
        return -1;
    }
    is_32_bit_ = (ident_[EI_CLASS] != ELFCLASS64);
    // 读取 elf 文件的文件头
    res = read_elf_ehdr();
    if (res < 0) {
        return -2;
    }
    DEBUG_LOG("init of read_elf_ehdr success");
    // 读取 elf 文件的段表
    // shdrs_ = reinterpret_cast<Elf_Shdr*>(malloc(ehdr_.e_shnum * sizeof(Elf_Shdr)));
    // if (shdrs_ == nullptr) {
    //     ERROR_LOG("init of malloc failed, err: %s", strerror(errno));
    //     return -3;
    // }
    res = read_elf_shdrs(ehdr_.e_shnum);
    if (res < 0) {
        return -4;
    }
    DEBUG_LOG("init of read_elf_shdrs success");
    return 0;
}

int ELFManager::read_elf_ehdr() {
    int res;
    if (is_32_bit_) {
        Elf32_Ehdr ehdr32;
        res = read_elf(0, &ehdr32, sizeof(ehdr32));
        if (res < 0) {
            return -1;
        }
        ehdr_.e_shoff = ehdr32.e_shoff;
        ehdr_.e_shnum = ehdr32.e_shnum;
        ehdr_.e_shentsize = ehdr32.e_shentsize;
    } else {
        Elf64_Ehdr ehdr64;
        res = read_elf(0, &ehdr64, sizeof(ehdr64));
        if (res < 0) {
            return -2;
        }
        ehdr_.e_shoff = ehdr64.e_shoff;
        ehdr_.e_shentsize = ehdr64.e_shentsize;
        ehdr_.e_shnum = ehdr64.e_shnum;
    }
    DEBUG_LOG("ehdr shoff: %d, shentsize: %d, shnum: %d", ehdr_.e_shoff, ehdr_.e_shentsize, ehdr_.e_shnum);
    return 0;
}

int ELFManager::read_elf_shdrs(unsigned int shnum) {
    shdrs_.resize(shnum);
    int res;
    int shsize = shnum * ehdr_.e_shentsize;
    if (is_32_bit_) {
        Elf32_Shdr shdrs32[shnum];
        res = read_elf(ehdr_.e_shoff, shdrs32, shsize);
        if (res < 0) {
            return -1;
        }
        for (size_t i = 0; i < shnum; ++i) {
            shdrs_[i].sh_type = shdrs32[i].sh_type;
            shdrs_[i].sh_offset = shdrs32[i].sh_offset;
            shdrs_[i].sh_size = shdrs32[i].sh_size;
            shdrs_[i].sh_link = shdrs32[i].sh_link;
            shdrs_[i].sh_entsize = shdrs32[i].sh_entsize;
        }
    } else {
        Elf64_Shdr shdrs64[shnum];
        res = read_elf(ehdr_.e_shoff, shdrs64, shsize);
        if (res < 0) {
            return -2;
        }
        for (size_t i = 0; i < shnum; ++i) {
            shdrs_[i].sh_type = shdrs64[i].sh_type;
            shdrs_[i].sh_offset = shdrs64[i].sh_offset;
            shdrs_[i].sh_size = shdrs64[i].sh_size;
            shdrs_[i].sh_link = shdrs64[i].sh_link;
            shdrs_[i].sh_entsize = shdrs64[i].sh_entsize;
        }
    }
    return 0;
}

int ELFManager::read_elf(int pos, void* buf, int count) {
    int res = lseek(fd_, pos, SEEK_SET);
    if (res < 0) {
        ERROR_LOG("read_elf of lseek failed, err: %s", strerror(errno));
        return -2;
    }
    ssize_t tmp_count = count;
    ssize_t already_read = 0;
    for (;;) {
        ssize_t res = read(fd_, buf, count);
        if (res == -1) {
            // 如果是中断导致，则在此循环
            if (errno == EINTR) {
                continue;
            }
            ERROR_LOG("read_elf of read failed, err: %s", strerror(errno));
            return -3;
        }
        if (res > 0) {
            buf = (reinterpret_cast<char*>(buf)) + res;
            count -= res;
            already_read += res;
        }
        // 读够了
        if (count == 0) {
            return 0;
        }
        // 读到了文件尾
        if (res == 0 && already_read != tmp_count) {
            ERROR_LOG("read_elf of read failed, just read: %d, expected: %d", already_read, tmp_count);
            return -4;
        }
    }
    return 0;
}

}  // namespace zhook
