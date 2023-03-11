#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "log.h"

namespace zhook {

static LOG_LEVEL global_log_level = LOG_DEBUG_LEVEL;

void Logger::fatal_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal(LOG_FATAL_LEVEL, fmt, ap);
    va_end(ap);
    exit(-1);
}

void Logger::error_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal(LOG_ERROR_LEVEL, fmt, ap);
    va_end(ap);
}

void Logger::warn_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal(LOG_WARN_LEVEL, fmt, ap);
    va_end(ap);
}

void Logger::info_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal(LOG_INFO_LEVEL, fmt, ap);
    va_end(ap);
}

void Logger::debug_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal(LOG_DEBUG_LEVEL, fmt, ap);
    va_end(ap);
}

const char* Logger::get_log_level_str(LOG_LEVEL log_level) {
    switch (log_level) {
    case LOG_FATAL_LEVEL:
        return "FATAL";
    case LOG_ERROR_LEVEL:
        return "ERROR";
    case LOG_WARN_LEVEL:
        return "WARN";
    case LOG_INFO_LEVEL:
        return "INFO";
    case LOG_DEBUG_LEVEL:
        return "DEBUG";
    default:
        return "UNKOWN_LOG_LEVEL";
    }
}

void Logger::log_internal(LOG_LEVEL log_level, const char* fmt, va_list ap) {
    if (log_level > global_log_level) {
        return;
    }
    char buf[1024];
    size_t bufLen = sizeof(buf);
    if (fmt != NULL) {
        vsnprintf(buf, bufLen, fmt, ap);
        buf[bufLen-1] = '\0';
    } else {
        buf[0] = '\0';
    }
    fprintf(stdout, "[zhook %s] %s \n", get_log_level_str(log_level), buf);
}

}  // namespace zhook
