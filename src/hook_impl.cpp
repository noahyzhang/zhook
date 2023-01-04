#include "common.h"
#include "hook_impl.h"

namespace zhook {

HookImpl::HookImpl(bfd* bfd_ptr) : bfd_(bfd_ptr) {}

int HookImpl::attach_func(void* func_plt, void* hook_func) {
    if (func_plt == nullptr) {
        ERROR_LOG("HookImpl::attach_func param func_plt is null");
        return -1;
    }
    unsigned long* tmp_ptr = reinterpret_cast<unsigned long*>(func_plt);
    auto iter = sys_hook_dict_.find(func_plt);
    // 第一次 attach 需要做备份
    if (iter == sys_hook_dict_.end()) {
        sys_hook_dict_[func_plt].old_addr = reinterpret_cast<void*>(*tmp_ptr);
    }
    sys_hook_dict_[func_plt].hook_func = hook_func;
    *tmp_ptr = reinterpret_cast<unsigned long>(hook_func);
    return 0;
}

int HookImpl::detach_func(void* func_plt) {
    if (func_plt == nullptr) {
        ERROR_LOG("HookImpl::detach_func param func_plt is null");
        return 0;
    }
    auto iter = sys_hook_dict_.find(func_plt);
    if (iter != sys_hook_dict_.end()) {
        sys_hook_dict_.erase(iter);
    }
    return 0;
}

}  // namespace zhook
