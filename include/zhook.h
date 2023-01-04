
#pragma once

namespace zhook {

/**
 * @brief 挂载系统函数
 * 
 * @param func_name 系统函数名
 * @param hook_func 要替换的函数
 * @return int 挂载是否成功，0 表示成功，非 0 表示失败
 */
int attach_func(const char* func_name, void* hook_func);

/**
 * @brief 卸载已挂载的系统函数
 * 
 * @param func_name 系统函数名
 * @return int 卸载是否成功，0 表示成功，非 0 表示失败
 */
int detach_func(const char* func_name);

/**
 * @brief 获取真实的函数地址（动态库 hook 中）
 * 
 * @param func_name 函数名
 * @return void* 真实函数地址
 */
void* get_real_func(const char* func_name);

}  // namespace zhook
