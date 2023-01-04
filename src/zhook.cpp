#include "core.h"
#include "zhook.h"


namespace zhook {

int attach_func(const char* func_name, void* hook_func) {
    return Core::get_instance().attach_func(func_name, hook_func);
}

int detach_func(const char* func_name) {
    return Core::get_instance().detach_func(func_name);
}

void* get_real_func(const char* func_name) {
    return Core::get_instance().get_real_func(func_name);
}

}  // namespace zhook
