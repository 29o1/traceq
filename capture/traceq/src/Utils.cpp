//
// Created by lidongyooo on 2026/2/6.
//

#include "Utils.h"
#include "TraceqCapture.h"


const std::vector<std::string> svc_names = {"io_setup 0", "io_destroy 1", "io_submit 2",
                                            "io_cancel 3", "io_getevents 4",
                                            "setxattr 5", "lsetxattr 6", "fsetxattr 7",
                                            "getxattr 8", "lgetxattr 9", "fgetxattr 10",
                                            "listxattr 11", "llistxattr 12", "flistxattr 13",
                                            "removexattr 14", "lremovexattr 15", "fremovexattr 16",
                                            "getcwd 17",
                                            "lookup_dcookie 18", "eventfd2 19", "epoll_create1 20",
                                            "epoll_ctl 21", "epoll_pwait 22", "dup 23", "dup3 24",
                                            "fcntl 25",
                                            "inotify_init1 26", "inotify_add_watch 27",
                                            "inotify_rm_watch 28", "ioctl 29", "ioprio_set 30",
                                            "ioprio_get 31", "flock 32",
                                            "mknodat 33", "mkdirat 34", "unlinkat 35",
                                            "symlinkat 36", "linkat 37", "renameat 38",
                                            "umount2 39", "mount 40", "pivot_root 41",
                                            "nfsservctl 42", "statfs 43", "fstatfs 44",
                                            "truncate 45", "ftruncate 46", "fallocate 47",
                                            "faccessat 48", "chdir 49", "fchdir 50",
                                            "chroot 51", "fchmod 52", "fchmodat 53", "fchownat 54",
                                            "fchown 55", "openat 56", "close 57", "vhangup 58",
                                            "pipe2 59", "quotactl 60",
                                            "getdents64 61", "lseek 62", "read 63", "write 64",
                                            "readv 65", "writev 66", "pread64 67", "pwrite64 68",
                                            "preadv 69", "pwritev 70",
                                            "sendfile 71", "pselect6 72", "ppoll 73",
                                            "signalfd4 74", "vmsplice 75", "splice 76", "tee 77",
                                            "readlinkat 78", "fstatat 79",
                                            "fstat 80", "sync 81", "fsync 82", "fdatasync 83",
                                            "sync_file_range 84", "timerfd_create 85",
                                            "timerfd_settime 86",
                                            "timerfd_gettime 87", "utimensat 88", "acct 89",
                                            "capget 90", "capset 91", "personality 92", "exit 93",
                                            "exit_group 94",
                                            "waitid 95", "set_tid_address 96", "unshare 97",
                                            "futex 98", "set_robust_list 99", "get_robust_list 100",
                                            "nanosleep 101",
                                            "getitimer 102", "setitimer 103", "kexec_load 104",
                                            "init_module 105", "delete_module 106",
                                            "timer_create 107", "timer_gettime 108",
                                            "timer_getoverrun 109", "timer_settime 110",
                                            "timer_delete 111", "clock_settime 112",
                                            "clock_gettime 113", "clock_getres 114",
                                            "clock_nanosleep 115", "syslog 116", "ptrace 117",
                                            "sched_setparam 118", "sched_setscheduler 119",
                                            "sched_getscheduler 120",
                                            "sched_getparam 121", "sched_setaffinity 122",
                                            "sched_getaffinity 123", "sched_yield 124",
                                            "sched_get_priority_max 125",
                                            "sched_get_priority_min 126",
                                            "sched_rr_get_interval 127", "restart_syscall 128",
                                            "kill 129", "tkill 130", "tgkill 131",
                                            "sigaltstack 132",
                                            "rt_sigsuspend 133", "rt_sigaction 134",
                                            "rt_sigprocmask 135", "rt_sigpending 136",
                                            "rt_sigtimedwait 137", "rt_sigqueueinfo 138",
                                            "rt_sigreturn 139",
                                            "setpriority 140", "getpriority 141", "reboot 142",
                                            "setregid 143", "setgid 144", "setreuid 145",
                                            "setuid 146", "setresuid 147", "getresuid 148",
                                            "setresgid 149", "getresgid 150", "setfsuid 151",
                                            "setfsgid 152", "times 153", "setpgid 154",
                                            "getpgid 155", "getsid 156", "setsid 157",
                                            "getgroups 158",
                                            "setgroups 159", "uname 160", "sethostname 161",
                                            "setdomainname 162", "getrlimit 163", "setrlimit 164",
                                            "getrusage 165", "umask 166", "prctl 167", "getcpu 168",
                                            "gettimeofday 169", "settimeofday 170", "adjtimex 171",
                                            "getpid 172", "getppid 173", "getuid 174",
                                            "geteuid 175", "getgid 176", "getegid 177",
                                            "gettid 178",
                                            "sysinfo 179", "mq_open 180", "mq_unlink 181",
                                            "mq_timedsend 182", "mq_timedreceive 183",
                                            "mq_notify 184", "mq_getsetattr 185", "msgget 186",
                                            "msgctl 187",
                                            "msgrcv 188", "msgsnd 189", "semget 190", "semctl 191",
                                            "semtimedop 192", "semop 193", "shmget 194",
                                            "shmctl 195", "shmat 196", "shmdt 197", "socket 198",
                                            "socketpair 199", "bind 200", "listen 201",
                                            "accept 202", "connect 203", "getsockname 204",
                                            "getpeername 205", "sendto 206", "recvfrom 207",
                                            "setsockopt 208",
                                            "getsockopt 209", "shutdown 210", "sendmsg 211",
                                            "recvmsg 212", "readahead 213", "brk 214", "munmap 215",
                                            "mremap 216", "add_key 217", "request_key 218",
                                            "keyctl 219", "clone 220", "execve 221", "mmap 222",
                                            "fadvise64 223", "swapon 224", "swapoff 225",
                                            "mprotect 226", "msync 227", "mlock 228", "munlock 229",
                                            "mlockall 230", "munlockall 231", "mincore 232",
                                            "madvise 233", "remap_file_pages 234", "mbind 235",
                                            "get_mempolicy 236", "set_mempolicy 237",
                                            "migrate_pages 238", "move_pages 239",
                                            "rt_tgsigqueueinfo 240", "perf_event_open 241",
                                            "accept4 242", "recvmmsg 243",
                                            "arch_specific_syscall 244",
                                            "wait4 260", "prlimit64 261", "fanotify_init 262",
                                            "fanotify_mark 263", "name_to_handle_at 264",
                                            "open_by_handle_at 265", "clock_adjtime 266",
                                            "syncfs 267", "setns 268", "sendmmsg 269",
                                            "process_vm_readv 270", "process_vm_writev 271",
                                            "kcmp 272", "finit_module 273", "sched_setattr 274",
                                            "sched_getattr 275", "renameat2 276", "seccomp 277",
                                            "getrandom 278", "memfd_create 279", "bpf 280",
                                            "execveat 281", "userfaultfd 282", "membarrier 283",
                                            "mlock2 284", "copy_file_range 285", "preadv2 286",
                                            "pwritev2 287", "pkey_mprotect 288", "pkey_alloc 289",
                                            "pkey_free 290", "statx 291"};

const std::vector<std::string> jni_func_names = { "reserved0", "reserved1", "reserved2", "reserved3", "GetVersion", "DefineClass", "FindClass",
                                 "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom",
                                 "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear",
                                 "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
                                 "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV", "NewObjectA",
                                 "GetObjectClass", "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
                                 "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA",
                                 "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV", "CallShortMethodA",
                                 "CallIntMethod", "CallIntMethodV", "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA",
                                 "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA",
                                 "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV",
                                 "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
                                 "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod",
                                 "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA", "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV",
                                 "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA",
                                 "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod",
                                 "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA", "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV",
                                 "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA",
                                 "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField", "GetShortField", "GetIntField",
                                 "GetLongField", "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField",
                                 "SetShortField", "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID", "CallStaticObjectMethod",
                                 "CallStaticObjectMethodV", "CallStaticObjectMethodA", "CallStaticBooleanMethod", "CallStaticBooleanMethodV",
                                 "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA", "CallStaticCharMethod",
                                 "CallStaticCharMethodV", "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA",
                                 "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV",
                                 "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA", "CallStaticDoubleMethod",
                                 "CallStaticDoubleMethodV", "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
                                 "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField", "GetStaticShortField",
                                 "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField",
                                 "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField",
                                 "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength",
                                 "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
                                 "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
                                 "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements",
                                 "GetFloatArrayElements", "GetDoubleArrayElements", "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements",
                                 "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
                                 "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion",
                                 "GetDoubleArrayRegion", "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion", "SetLongArrayRegion",
                                 "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
                                 "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef",
                                 "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType"};


std::vector<std::string> Utils::str_split(const std::string& s, char symbol) {
    std::vector<std::string> res;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(symbol, pos);
        if (comma == std::string::npos) {
            comma = s.size();
        }
        res.push_back(s.substr(pos, comma - pos));
        pos = comma + 1;
    }
    return res;
}

int Utils::get_data_width(cs_insn *insn, cs_arm64 *arm64) {
    if (!insn || !arm64) return 0;

    switch (insn->id) {
        case ARM64_INS_LDARB:
        case ARM64_INS_LDAXRB:
        case ARM64_INS_LDXRB:
        case ARM64_INS_STXRB:
        case ARM64_INS_STLXRB:
        case ARM64_INS_STLRB:
        case ARM64_INS_SWPB:
        case ARM64_INS_CASB:
        case ARM64_INS_CASALB:
        case ARM64_INS_CASAB:
        case ARM64_INS_LDADDB:
        case ARM64_INS_LDADDLB:
        case ARM64_INS_STADDB:
        case ARM64_INS_LDEORB:
        case ARM64_INS_STEORB:
            return 1;

        case ARM64_INS_LDAXRH:
        case ARM64_INS_LDXRH:
        case ARM64_INS_STXRH:
        case ARM64_INS_STLXRH:
        case ARM64_INS_LDARH:
        case ARM64_INS_STLRH:
        case ARM64_INS_SWPH:
        case ARM64_INS_CASH:
        case ARM64_INS_CASALH:
        case ARM64_INS_CASAH:
        case ARM64_INS_LDADDH:
        case ARM64_INS_LDADDLH:
        case ARM64_INS_STADDH:
        case ARM64_INS_LDEORH:
        case ARM64_INS_STEORH:
            return 2;
    }

    int reg_op_idx = 0;
    switch (insn->id) {
        case ARM64_INS_STXR:
        case ARM64_INS_STXP:
        case ARM64_INS_STLXR:
        case ARM64_INS_STLXP:
            reg_op_idx = 1;
            break;
    }

    if (reg_op_idx < arm64->op_count) {
        arm64_reg reg = arm64->operands[reg_op_idx].reg;
        if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WZR || reg == ARM64_REG_WSP) return 4;
        if ((reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) || reg == ARM64_REG_XZR || reg == ARM64_REG_SP || reg == ARM64_REG_FP || reg == ARM64_REG_LR) return 8;
    }

    return 8;
}


bool Utils::get_register_value(arm64_reg reg, _GumArm64CpuContext *ctx, __uint128_t &value) {
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) { value = 0; return true; }
    if (reg == ARM64_REG_WSP) { value = uint32_t(ctx->sp); return true; }
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        int idx = reg - ARM64_REG_W0;
        value = uint32_t(idx < 29 ? ctx->x[idx] : idx == 29 ? ctx->fp : ctx->lr);
    } else if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        int idx = reg - ARM64_REG_X0;
        value = ctx->x[idx];
    } else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        int idx = reg - ARM64_REG_Q0;
        memcpy(&value, ctx->v[idx].q, 16);
    } else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        int idx = reg - ARM64_REG_D0;
        value = 0;
        memcpy(&value, ctx->v[idx].q, 8);
    } else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        int idx = reg - ARM64_REG_S0;
        value = 0;
        memcpy(&value, ctx->v[idx].q, 4);
    } else if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        int idx = reg - ARM64_REG_H0;
        value = ctx->v[idx].h;
    } else if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        int idx = reg - ARM64_REG_B0;
        value = ctx->v[idx].b;
    }  else if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        int idx = reg - ARM64_REG_V0;
        memcpy(&value, ctx->v[idx].q, 16);
    } else {
        switch (reg) {
            case ARM64_REG_SP:
                value = ctx->sp;
                break;
            case ARM64_REG_FP:
                value = ctx->fp;
                break;      // ARM64_REG_X29
            case ARM64_REG_LR:
                value = ctx->lr;
                break;      // ARM64_REG_X30
            case ARM64_REG_NZCV:
                value = ctx->nzcv;
                break;
            default:
                return false;
        }
    }

    return true;
}

const char *Utils::get_arm64_reg_name(arm64_reg reg) {
    static thread_local char reg_name[16];

    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        snprintf(reg_name, sizeof(reg_name), "w%d", reg - ARM64_REG_W0);
        return reg_name;
    }

    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        snprintf(reg_name, sizeof(reg_name), "x%d", reg - ARM64_REG_X0);
        return reg_name;
    }

    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        snprintf(reg_name, sizeof(reg_name), "b%d", reg - ARM64_REG_B0);
        return reg_name;
    }

    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        snprintf(reg_name, sizeof(reg_name), "h%d", reg - ARM64_REG_H0);
        return reg_name;
    }

    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        snprintf(reg_name, sizeof(reg_name), "s%d", reg - ARM64_REG_S0);
        return reg_name;
    }

    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        snprintf(reg_name, sizeof(reg_name), "d%d", reg - ARM64_REG_D0);
        return reg_name;
    }

    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        snprintf(reg_name, sizeof(reg_name), "q%d", reg - ARM64_REG_Q0);
        return reg_name;
    }

    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        snprintf(reg_name, sizeof(reg_name), "v%d", reg - ARM64_REG_V0);
        return reg_name;
    }

    switch (reg) {
        case ARM64_REG_SP:
            return "sp";
        case ARM64_REG_FP:
            return "fp";
        case ARM64_REG_LR:
            return "lr";
        case ARM64_REG_NZCV:
            return "nzcv";
        case ARM64_REG_WZR:
            return "wzr";
        case ARM64_REG_XZR:
            return "xzr";
        default:
            return "unk";
    }
}


static const char hex_chars[] = "0123456789abcdef";

void Utils::append_uint64_hex(char* buff, int& counter, uint64_t val) {
    if (val == 0) {
        buff[counter++] = '0';
        return;
    }

    char temp[16];
    int i = 0;
    while (val) {
        temp[i++] = hex_chars[val & 0xF];
        val >>= 4;
    }
    while (i > 0) {
        buff[counter++] = temp[--i];
    }
}

void Utils::append_uint64_hex_fixed(char* buff, int& counter, uint64_t val) {
    for (int i = 15; i >= 0; --i) {
        buff[counter + i] = hex_chars[val & 0xF];
        val >>= 4;
    }
    counter += 16;
}

void Utils::format_uint128_hex(__uint128_t value, int& counter, char* buff) {
    uint64_t high = value >> 64;
    uint64_t low = value;
    if (high > 0) {
        append_uint64_hex(buff, counter, high);
        append_uint64_hex_fixed(buff, counter, low);
    } else {
        append_uint64_hex(buff, counter, low);
    }
}

void Utils::auto_snprintf(int& counter, char* buff, const char* __restrict __format, ...) {
    if (!buff || !__format) {
        return;
    }

    int remaining = BUFFER_SIZE - counter;
    if (remaining <= 0) {
        return;
    }

    va_list args;
    va_start(args, __format);
    int written = vsnprintf(buff + counter, remaining, __format, args);
    va_end(args);
    if (written > 0) {
        counter += (written < remaining) ? written : remaining - 1;
    }
}
