//
// Created by lidongyooo on 2026/2/5.
//


#include "TraceqCapture.h"
#include "Utils.h"

gboolean module_symbols_cb(const GumSymbolDetails * details, gpointer user_data) {
    auto *instance = TraceqCapture::get_instance();
    if (details && details->name && details->address && details->section != nullptr &&
        (details->section->protection & GUM_PAGE_READ)) {
        instance->func_maps[details->address] = details->name;
    }

    // if (details->is_global) {
    //     size_t global_addr = gum_module_find_global_export_by_name(details->name);
    //     if (global_addr > 0) {
    //         instance->func_maps[global_addr] = details->name;
    //     }
    // }

    return true;
}

gboolean module_dependency_cb (const GumDependencyDetails * details, gpointer user_data) {
    auto gum_module = gum_process_find_module_by_name(details->name);
    if (gum_module != nullptr) {
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
    }
    return true;
}

gboolean module_enumerate (GumModule * module, gpointer user_data) {
    auto instance = TraceqCapture::get_instance();
    const char *module_name = gum_module_get_name(module);

    if (instance->modules.count(module_name) > 0) {
        return true;
    }

    gum_stalker_exclude(instance->_stalker, gum_module_get_range(module));
    return true;
}

extern "C" __attribute__((visibility("default")))
void traceq_init(const char *module_names, char *trace_file_path, int thread_id, TraceqCaptureOptions* options) {

    gum_init();
    auto code_signing_policy = gum_process_get_code_signing_policy();
    LOGE("Gum code signing policy before init: %s",
         gum_code_signing_policy_to_string(code_signing_policy));
#if PLATFORM_IOS
    if (code_signing_policy != GUM_CODE_SIGNING_OPTIONAL) {
        gum_process_set_code_signing_policy(GUM_CODE_SIGNING_OPTIONAL);
        LOGE("Gum code signing policy forced to: %s",
             gum_code_signing_policy_to_string(gum_process_get_code_signing_policy()));
    }
#endif

    TraceqCapture *instance = TraceqCapture::get_instance();
    instance->reset_session();
    memcpy(&instance->options, options, sizeof(TraceqCaptureOptions));

    instance->_stalker = gum_stalker_new();
    gum_stalker_set_trust_threshold(instance->_stalker, 0);
    gum_stalker_set_ratio(instance->_stalker, 2);
    if (instance->options.mode == TRACEQ_MODE_STABLE) {
        gum_stalker_set_trust_threshold(instance->_stalker, 2);
        gum_stalker_set_ratio(instance->_stalker, 5);
    }

    auto module_names_vector = Utils::str_split(module_names, ',');
    for (const auto &module_name: module_names_vector) {
        auto *gum_module = gum_process_find_module_by_name(module_name.c_str());
        if (gum_module == nullptr) {
            LOGE("module not found: %s", module_name.c_str());
            continue;
        }
        auto &module_map = instance->modules[module_name];
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
        gum_module_enumerate_dependencies(gum_module, module_dependency_cb, nullptr);
        auto *gum_module_range = gum_module_get_range(gum_module);
        module_map["base"] = gum_module_range->base_address;
        module_map["size"] = gum_module_range->size;
    }

    gum_process_enumerate_modules(module_enumerate, nullptr);

    size_t path_len = strlen(trace_file_path);
    if (path_len >= sizeof(instance->trace_file_path)) {
        path_len = sizeof(instance->trace_file_path) - 1;
    }
    memcpy(instance->trace_file_path, trace_file_path, path_len);
    instance->trace_file_path[path_len] = '\0';
    instance->trace_thread_id = thread_id;
    instance->trace_file = std::ofstream(instance->trace_file_path, std::ios::out | std::ios::trunc);

    for (const auto& svc_name : svc_names) {
        auto svc_name_vector = Utils::str_split(svc_name, ' ');
        instance->svc_func_maps[std::stoi(svc_name_vector.at(1))] = svc_name_vector.at(0);
    }

#if PLATFORM_ANDROID
    auto libart_module = gum_process_find_module_by_name("libart.so");
    GumAddress JNI_GetCreatedJavaVMs_addr = 0;
    if (libart_module != nullptr) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_symbol_by_name(
            libart_module, "JNI_GetCreatedJavaVMs");
        if (JNI_GetCreatedJavaVMs_addr == 0) {
            JNI_GetCreatedJavaVMs_addr = gum_module_find_export_by_name(
                libart_module, "JNI_GetCreatedJavaVMs");
        }
    }
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_global_export_by_name(
            "JNI_GetCreatedJavaVMs");
    }
    if (JNI_GetCreatedJavaVMs_addr != 0) {
        typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
        auto *jni_get_created_vms = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(JNI_GetCreatedJavaVMs_addr);
        jsize vm_count = 1;
        auto **vms = new JavaVM*[vm_count];
        jint result = jni_get_created_vms(vms, vm_count, &vm_count);
        if (result == JNI_OK && vm_count > 0) {
            instance->java_vm = vms[0];
            LOGE("成功获取JavaVM: %p", instance->java_vm);
        } else {
            LOGE("获取JavaVM失败，错误码: %d", result);
        }

        delete[] vms;
    }
#    endif

}

extern "C" __attribute__((visibility("default")))
void traceq_start() {
    TraceqCapture *instance = TraceqCapture::get_instance();
    instance->follow();
}

extern "C" __attribute__((visibility("default")))
void traceq_stop() {
    TraceqCapture *instance = TraceqCapture::get_instance();
    instance->unfollow();
}

// Compatibility with the original text-capture loader ABI.
extern "C" __attribute__((visibility("default")))
void init(const char* modules,char* path,int thread,TraceqCaptureOptions* options){traceq_init(modules,path,thread,options);}
extern "C" __attribute__((visibility("default"))) void run(){traceq_start();}
extern "C" __attribute__((visibility("default"))) void unrun(){traceq_stop();}

int main() {
    printf("xxx %p", main);
}
