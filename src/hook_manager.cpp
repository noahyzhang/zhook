#include <inttypes.h>
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

int HookManager::get_all_so_info() {
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
        ERROR_LOG("HookManager::get_all_so_info use fopen failed, err: %s", strerror(errno));
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
        while (std::isspace(line[pathname_pos]) && pathname_pos < (sizeof(line) - 1)) {
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
        // 或者如果 offset bu webuwe
        if (offset)

    }
}

}  // namespace zhook
