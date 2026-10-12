/*
 * libtripwire_timewarp.c - Time Dilation & Anti-Analysis Neutralization Preload Library
 *
 * Intercepts POSIX time and sleep syscalls to defeat sandbox-evasion and delayed payloads:
 * - clock_gettime, gettimeofday: Accelerates virtual clock forward
 * - nanosleep, sleep, usleep: Instantly warps time forward without waiting
 * - getpid, uname: Sanitizes environment fingerprints
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <dlfcn.h>

static int (*real_clock_gettime)(clockid_t clk_id, struct timespec *tp) = NULL;
static int (*real_gettimeofday)(struct timeval *tv, struct timezone *tz) = NULL;
static int (*real_nanosleep)(const struct timespec *req, struct timespec *rem) = NULL;
static unsigned int (*real_sleep)(unsigned int seconds) = NULL;

// Virtual time offset in seconds (accumulated across skipped sleeps)
static long long virtual_time_offset_sec = 0;

__attribute__((constructor))
static void init_timewarp(void) {
    real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    real_gettimeofday  = dlsym(RTLD_NEXT, "gettimeofday");
    real_nanosleep     = dlsym(RTLD_NEXT, "nanosleep");
    real_sleep         = dlsym(RTLD_NEXT, "sleep");
    
    const char *initial_warp = getenv("TRIPWIRE_WARP_OFFSET");
    if (initial_warp) {
        virtual_time_offset_sec = atoll(initial_warp);
    }
}

// Intercept sleep(): Instantly skip execution time while advancing virtual clock
unsigned int sleep(unsigned int seconds) {
    virtual_time_offset_sec += seconds;
    // Log evasion bypass attempt
    const char *log_path = getenv("TRIPWIRE_WARP_LOG");
    if (log_path) {
        FILE *f = fopen(log_path, "a");
        if (f) {
            fprintf(f, "[TIMEWARP] Intercepted sleep(%u). Virtual clock warped forward by +%us.\n", seconds, seconds);
            fclose(f);
        }
    }
    // Return immediately to force execution of delayed payload
    return 0;
}

// Intercept nanosleep()
int nanosleep(const struct timespec *req, struct timespec *rem) {
    if (req) {
        virtual_time_offset_sec += req->tv_sec;
    }
    if (rem) {
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }
    return 0;
}

// Intercept clock_gettime(): Return real time PLUS virtual offset
int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    if (!real_clock_gettime) init_timewarp();
    int ret = real_clock_gettime(clk_id, tp);
    if (ret == 0 && tp) {
        tp->tv_sec += virtual_time_offset_sec;
    }
    return ret;
}

// Intercept gettimeofday()
int gettimeofday(struct timeval *tv, struct timezone *tz) {
    if (!real_gettimeofday) init_timewarp();
    int ret = real_gettimeofday(tv, tz);
    if (ret == 0 && tv) {
        tv->tv_sec += virtual_time_offset_sec;
    }
    return ret;
}
