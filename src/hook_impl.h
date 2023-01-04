#pragma once

#include <bfd.h>
#include <map>
#include "asm_helper.h"

namespace zhook {

class HookImpl {
public:
    struct HookInfo {
        char backup[FAR_JMP_CODE_LEN];
        void* hook_func;
        void* trampoline_func;
    };
    struct SysHookInfo {
        void* hook_func;
        void* old_addr;
    };

    explicit HookImpl(bfd* bfd_ptr);
    ~HookImpl() = default;
    int attach_func(void* func_plt, void* hook_func);
    int detach_func(void* func_plt);

private:
    bfd* bfd_;
    std::map<void*, HookInfo> hook_dict_;
    std::map<void*, SysHookInfo> sys_hook_dict_;
};

}  // namespace zhook
