#include <stdarg.h>

namespace zhook {

// 定义日志级别
enum LOG_LEVEL {
    LOG_FATAL_LEVEL = 0,
    LOG_ERROR_LEVEL,
    LOG_WARN_LEVEL,
    LOG_INFO_LEVEL,
    LOG_DEBUG_LEVEL,
};

class Logger {
public:
    static void fatal_log(const char* fmt, ...);
    static void error_log(const char* fmt, ...);
    static void warn_log(const char* fmt, ...);
    static void info_log(const char* fmt, ...);
    static void debug_log(const char* fmt, ...);

private:
    static const char* get_log_level_str(LOG_LEVEL log_level);
    static void log_internal(LOG_LEVEL log_level, const char* fmt, va_list ap);
};

};  // namespace zhook
