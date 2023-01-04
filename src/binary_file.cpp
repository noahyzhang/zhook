#include <vector>
#include <string.h>

#ifdef HAVE_BFD_DEMANGLE
#include <bfd.h>
#else
#include <cxxabi.h>
#endif

#include "common.h"
#include "binary_file.h"

namespace zhook {

int BinaryFile::init(const char* file_name) {
    destroy();
    // 初始化 bfd 库
    bfd_init();
    bfd_ = bfd_openr(file_name, nullptr);
    if (bfd_ == nullptr) {
        ERROR_LOG("BinaryFile::init of bfd_openr failed, err: %s", strerror(errno));
        return -1;
    }
    if (bfd_check_format(bfd_, bfd_object) == false) {
        ERROR_LOG("BinaryFile::init of bfd_check_format failed, err: %s", strerror(errno));
        return -2;
    }
    // 初始化 ELFManager
    elf_manager_ = new ELFManager();
    if (elf_manager_->init(bfd_->filename) < 0) {
        ERROR_LOG("BinaryFile::init of ELFManager init failed");
        return -1;
    }
    if (init_symbols(SYM_FUNC) < 0) {
        ERROR_LOG("BinaryFile::init of init_symbols failed");
        return -3;
    }
    if (init_relsym() < 0) {
        ERROR_LOG("BinaryFile::init of init_relsym failed");
        return -4;
    }
    return 0;
}

void BinaryFile::destroy() {
    if (elf_manager_) {
        delete elf_manager_;
        elf_manager_ = nullptr;
    }
    if (bfd_) {
        bfd_close(bfd_);
        bfd_ = nullptr;
    }
    symbol_dict_.clear();
    relsym_dict_.clear();
}

int BinaryFile::get_symbol(const char* symbol_name, std::shared_ptr<Symbol> symbol) {
    auto iter = symbol_dict_.find(symbol_name);
    if (iter != symbol_dict_.end()) {
        symbol->addr = iter->second.addr;
        symbol->size = iter->second.size;
        return 0;
    }
    return -1;
}

int BinaryFile::get_relocs(const char* symbol_name, std::shared_ptr<RelSym> rel_sym) {
    auto iter = relsym_dict_.find(symbol_name);
    if (iter != relsym_dict_.end()) {
        rel_sym->pgot = iter->second.pgot;
        rel_sym->real_name = iter->second.real_name;
        return 0;
    }
    return -1;
}

int BinaryFile::init_symbols(SYM_FLAG sym_flag) {
    // 获取到 ELF 文件的所有符号
    auto sym_arr = std::make_shared<std::vector<Elf_SymbolSection>>();
    if (elf_manager_ && elf_manager_->get_elf_symtab(sym_arr) < 0) {
        ERROR_LOG("BinaryFile::init_symbols of get_elf_symtab failed");
        return -2;
    }
    int type = 0;
    if (sym_flag & SYM_FUNC) {
        type = STT_FUNC;
    }
    for (const auto& sym : *sym_arr) {
        char* name = sym.name;
        bfd_vma value = sym.value;
        if (sym.type != type || value == 0 || sym.shndx == 0) {
            continue;
        }
#ifdef HAVE_BFD_DEMANGLE
        #define DMGL_PARAMS  (1 << 0)   // Include function args
        #define DMGL_ANSI    (1 << 1)   // Include const, volatile, etc
        char* demangle_name = bfd_demangle(nullptr, name, DMGL_PARAMS | DMGL_ANSI);
        if (demangle_name) {
            name = demangle_name;
        }
#else
        // FIXME: 规避 libstd++ 低版本 demangle("FT_SUPERDOC_cmp") 出 core 的 bug
        if (strcmp(name, "FT_SUPERDOC_cmp") == 0) {
            symbol_dict_[name].addr = reinterpret_cast<void*>(value);
            symbol_dict_[name].size = sym.size;
            continue;
        }
        int status;
        char* demangle_name = abi::__cxa_demangle(name, nullptr, nullptr, &status);
        if (status == 0) {
            name = demangle_name;
        }
#endif
        symbol_dict_[name].addr = reinterpret_cast<void*>(value);
        symbol_dict_[name].size = sym.size;
        if (demangle_name != nullptr) {
            free(demangle_name);
        }
    }
    return 0;
}

int BinaryFile::init_relsym() {
    // 获取到 ELF 文件的重定位符号
    auto relsym_arr = std::make_shared<std::vector<Elf_RealSymbolSection>>();
    if (elf_manager_ && elf_manager_->get_elf_relsym(relsym_arr) < 0) {
        ERROR_LOG("BinaryFile::init_relsym of get_elf_relsym failed");
        return -1;
    }
    auto dyn_sym_arr = std::make_shared<std::vector<Elf_SymbolSection>>();
    if (elf_manager_ && elf_manager_->get_elf_dyn_symtab(dyn_sym_arr) < 0) {
        ERROR_LOG("BinaryFile::init_relsym of get_elf_dyn_symtab failed");
        return -2;
    }
    for (const auto& relsym : *relsym_arr) {
        if (relsym.type != R_X86_64_JUMP_SLOT) {
            continue;
        }
        char* name = (*dyn_sym_arr)[relsym.symid].name;
#ifdef HAVE_BFD_DEMANGLE
        #define DMGL_PARAMS  (1 << 0)   // Include function args
        #define DMGL_ANSI    (1 << 1)   // Include const, volatile, etc
        char* demangle_name = bfd_demangle(nullptr, name, DMGL_PARAMS | DMGL_ANSI);
        if (demangle_name) {
            name = demangle_name;
        }
#else
        int status;
        char* demangle_name = abi::__cxa_demangle(name, nullptr, nullptr, &status);
        if (status == 0) {
            name = demangle_name;
        }
#endif
        relsym_dict_[name].real_name = (*dyn_sym_arr)[relsym.symid].name;
        relsym_dict_[name].pgot = reinterpret_cast<void*>(relsym.offset);
        DEBUG_LOG("BinaryFile::init_relsym get relsym of name: %s, pgot:0x%lx, addr: 0x%lx",
            name, relsym_dict_[name].pgot, relsym_dict_[name].real_name.c_str());
        if (demangle_name) {
            free(demangle_name);
        }
    }
    return 0;
}

}  // namespace zhook
