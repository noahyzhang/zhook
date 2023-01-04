#pragma once

#include <map>
#include <string>
#include <memory>
#include <bfd.h>
#include "elf_manager.h"

namespace zhook {

class BinaryFile {
public:
    struct Symbol {
        void* addr;
        unsigned long size;
    };
    struct RelSym {
        void* pgot;
        std::string real_name;
    };
    int init(const char* file_name);
    int get_symbol(const char* symbol_name, std::shared_ptr<Symbol> symbol);
    int get_relocs(const char* symbol_name, std::shared_ptr<RelSym> rel_sym);

    bfd* get_bfd() {
        return bfd_;
    }

private:
    typedef enum {
        SYM_FUNC = 1,
        SYM_OBJECT = 2
    } SYM_FLAG;
    void destroy();
    int init_symbols(SYM_FLAG sym_flag);
    int init_relsym();

private:
    ELFManager* elf_manager_{nullptr};
    bfd* bfd_{nullptr};
    std::map<std::string, Symbol> symbol_dict_;
    std::map<std::string, RelSym> relsym_dict_;
};

}  // namespace zhook
