#pragma once

#include "log.h"

namespace zhook {

// 封装日志宏
#define FATAL_LOG(fmt, ...) Logger::fatal_log(fmt, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) Logger::error_log(fmt, ##__VA_ARGS__)
#define WARN_LOG(fmt, ...)  Logger::warn_log(fmt, ##__VA_ARGS__)
#define INFO_LOG(fmt, ...)  Logger::info_log(fmt, ##__VA_ARGS__)
#define DEBUG_LOG(fmt, ...)  Logger::debug_log(fmt, ##__VA_ARGS__)

};  // namespace zhook
