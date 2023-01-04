#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <memory>
#include "common.h"
#include "hook_manager.h"

namespace zhook {

int HookManager::init() {
    if (is_inited_) {
        return 0;
    }
    // 获取到当前程序的二进制
    char proc_exec[32];
    char file_name[MAX_PATH_SIZE];
    pid_t pid = getpid();
    snprintf(proc_exec, sizeof(proc_exec), "/proc/%d/exe", pid);
    memset(file_name, 0, sizeof(file_name));
    if (readlink(proc_exec, file_name, sizeof(file_name)) < 0) {
        ERROR_LOG("HookManager::init of readlink failed, err: %s", strerror(errno));
        return -1;
    }
    // 初始化 BinaryFile
    bf_ = new BinaryFile();
    if (bf_->init(file_name) < 0) {
        ERROR_LOG("HookManager::init of init BinaryFile obj failed");
        return -2;
    }
    // 初始化 HookImpl
    hook_impl_ = new HookImpl(bf_->get_bfd());
    is_inited_ = true;
    return 0;
}

int HookManager::attach_func(const char* func_name, void* hook_func) {
    auto rel_sym = std::make_shared<BinaryFile::RelSym>();
    if (bf_->get_relocs(func_name, rel_sym) < 0) {
        ERROR_LOG("HookManager::attach_func of BinaryFile get_relocs failed");
        return -1;
    }
    return hook_impl_->attach_func(rel_sym->pgot, hook_func);
}

int HookManager::detach_func(const char* func_name) {
    auto rel_sym = std::make_shared<BinaryFile::RelSym>();
    if (bf_->get_relocs(func_name, rel_sym) < 0) {
        ERROR_LOG("HookManager::detach_func of BinaryFile get_relocs failed");
        return -1;
    }
    return hook_impl_->detach_func(rel_sym->pgot);
}

void* HookManager::get_real_func(const char* func_name) {
    auto rel_sym = std::make_shared<BinaryFile::RelSym>();
    if (bf_->get_relocs(func_name, rel_sym) < 0) {
        ERROR_LOG("HookManager::get_real_func of BinaryFile get_relocs failed");
        return nullptr;
    }
    void* real_func = reinterpret_cast<void*>(dlsym(RTLD_NEXT, rel_sym->real_name.c_str()));
    if (real_func) {
        ERROR_LOG("HookManager::get_real_func of dlsym failed, err: %s", strerror(errno));
        return nullptr;
    }
    return real_func;
}

}  // namespace zhook
