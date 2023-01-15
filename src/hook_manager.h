#pragma once

#include "binary_file.h"
#include "hook_impl.h"

namespace zhook {

#define MAX_PATH_SIZE 512

class HookManager {
public:
    HookManager() = default;
    ~HookManager() = default;

    int init();
    int attach_func(const char* func_name, void* hook_func);
    int detach_func(const char* func_name);
    void* get_real_func(const char* func_name);

private:
    int get_all_so_info();

private:
    bool is_inited_{false};
    BinaryFile* bf_{nullptr};
    HookImpl* hook_impl_{nullptr};
};

}  // namespace zhook
