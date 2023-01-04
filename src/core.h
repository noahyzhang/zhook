#pragma once

#include <mutex>
#include "hook_manager.h"

namespace zhook {

class Core {
public:
    ~Core();
    Core(const Core&) = delete;
    Core& operator=(const Core&) = delete;
    Core(Core&&) = delete;
    Core& operator=(Core&&) = delete;
    // 单例模式
    static Core& get_instance() {
        static Core instance;
        static std::once_flag run_once_flag;
        std::call_once(run_once_flag, [](){ instance.init(); });
        return instance;
    }

    int attach_func(const char* func_name, void* hook_func);
    int detach_func(const char* func_name);
    void* get_real_func(const char* func_name);

private:
    Core() = default;
    int init();

private:
    HookManager* hook_manager_;
};

}  // namespace zhook
