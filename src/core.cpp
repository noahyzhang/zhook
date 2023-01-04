#include "common.h"
#include "core.h"

namespace zhook {

Core::~Core() {
    if (hook_manager_) {
        delete hook_manager_;
    }
}

int Core::init() {
    hook_manager_ = new HookManager();
    if (hook_manager_->init() < 0) {
        ERROR_LOG("Core::init of HookManager init failed");
        return -1;
    }
    return 0;
}

int Core::attach_func(const char* func_name, void* hook_func) {
    return hook_manager_->attach_func(func_name, hook_func);
}

int Core::detach_func(const char* func_name) {
    return hook_manager_->detach_func(func_name);
}

void* Core::get_real_func(const char* func_name) {
    return hook_manager_->get_real_func(func_name);
}

}  // namespace zhook
