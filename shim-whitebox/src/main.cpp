#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <chrono>
#include <jni.h>
#include <sys/mman.h>
#include <set>
#include <sstream>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <link.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fstream>
#include "json.hpp"
#include "data.hpp"
#include "QBDI.h"

#define LOG_ERROR(...) console->error(__VA_ARGS__)
#define LOG_INFO(...)  console->info(__VA_ARGS__)

using json = nlohmann::json;
using namespace std::chrono;
using namespace QBDI;

static auto console = spdlog::stdout_color_mt("console");

static constexpr const char* R2PAY_LIB = "libnative-lib.so";
static uintptr_t base_address = 0;

static JavaVM* jvm = nullptr;
static JNIEnv* env = nullptr;

using gXftm3iswpkVgBNDUp_t = jbyteArray(*)(JNIEnv*, jobject, jbyteArray, jbyte);
static gXftm3iswpkVgBNDUp_t gXftm3iswpkVgBNDUp = nullptr;

extern "C" {
  JNIEXPORT void InitializeSignalChain() {}
  JNIEXPORT void ClaimSignalChain() {}
  JNIEXPORT void UnclaimSignalChain() {}
  JNIEXPORT void InvokeUserSignalHandler() {}
  JNIEXPORT void EnsureFrontOfChain() {}
  JNIEXPORT void AddSpecialSignalHandlerFn() {}
  JNIEXPORT void RemoveSpecialSignalHandlerFn() {}
}

enum class INJECTION_MODE {
  XOR   = 0,
  CONST = 1
};

uintptr_t get_base_address(const std::string& libname) {
  struct info_t {
    const std::string& lib;
    uintptr_t& base;
  };

  uintptr_t base = 0;
  info_t info {
    .lib = libname,
    .base = base
  };

  dl_iterate_phdr([] (dl_phdr_info* info, size_t, void* data) {
      info_t& output = *reinterpret_cast<info_t*>(data);
      if (info->dlpi_name == nullptr) {
        return 0;
      }
      if (std::string(info->dlpi_name).find(output.lib) != std::string::npos) {
        output.base = info->dlpi_addr;
        return 1;
      }
      return 0;
  }, reinterpret_cast<void*>(&info));
  return base;
}

inline jbyteArray to_jarray(const std::string& input, jbyte*& ptr) {
  jbyteArray array = env->NewByteArray(input.size() + 1);
  ptr = env->GetByteArrayElements(array, nullptr);
  memcpy(ptr, input.c_str(), input.size());
  env->SetByteArrayRegion(array, 0, input.size() + 1, ptr);
  return array;
}

inline std::vector<uint8_t> from_jbytes(jbyteArray out) {
  size_t encrypt_len = env->GetArrayLength(out);
  uint8_t* encrypt_ptr = reinterpret_cast<uint8_t*>(env->GetByteArrayElements(out, nullptr));
  std::vector<uint8_t> encrypted = {encrypt_ptr, encrypt_ptr + encrypt_len};
  env->ReleaseByteArrayElements(out, reinterpret_cast<jbyte*>(encrypt_ptr), 0);
  return encrypted;
}


inline std::vector<uint8_t> encrypt(const std::string& input) {
  jbyte* ptr = nullptr;
  jbyteArray array = to_jarray(input, ptr);
  jbyteArray out = gXftm3iswpkVgBNDUp(env, nullptr, array, 0xF0);
  env->ReleaseByteArrayElements(array, ptr, 0);
  return from_jbytes(out);

}
inline std::string to_hex(const std::vector<uint8_t>& raw, size_t idx = 0) {
  std::string encrypted_str;
  for (size_t i = idx; i < raw.size(); ++i) {
    encrypted_str += fmt::format("{:02x}", static_cast<uint8_t>(raw[i]));
  }
  return encrypted_str;
}

inline size_t get_error(const std::vector<uint8_t>& ref, const std::vector<uint8_t>& faulted) {
  if (ref.size() != faulted.size()) {
    console->error("Comparing two vectors with different size!");
    std::abort();
  }
  size_t count = 0;
  for (size_t i = 0; i < ref.size(); ++i) {
    if (ref[i] != faulted[i]) {
      ++count;
    }
  }
  return count;
}

inline void dump_data_section(const std::string& output) {
  /*
   * $ readelf -S ./libnative-lib.so
   * [18] .data             PROGBITS         0000000000127000  00117000
   *    000000000008d49f  0000000000000000  WA       0     0     8
   */
  std::ofstream ofs{fmt::format("/data/local/tmp/{}", output)};
  const char* start = reinterpret_cast<const char*>(base_address + /* .data[vaddr] */ 0x127000);
  ofs.write(start, /* sizeof(.data) */ 0x8d49f);
  LOG_INFO(".data section dumped here: /data/local/tmp/{}", output);
}

void run_shim() {
  std::string pin_amount = "0000123400004567";
  jbyte* ptr = nullptr;
  jbyteArray array = to_jarray(pin_amount, ptr);
  jbyteArray jencrypted_buffer = gXftm3iswpkVgBNDUp(env, nullptr, array, 0xF0);

  const std::vector<uint8_t> encrypted_buffer = from_jbytes(jencrypted_buffer);
  std::string ref_str = to_hex(encrypted_buffer, /* Skip first byte */ 1);
  LOG_INFO("{} --> {}", pin_amount, ref_str);
  env->ReleaseByteArrayElements(array, ptr, 0);
}

void trace_memory_accesses(const std::string& pin_amount) {
  static const size_t STACK_SIZE = 0x100000; // 1MB
  uint8_t *fakestack = nullptr;

  using trace_t = std::vector<std::array<uintptr_t, 3>>; // Not the better data
                                                         // structure but it's straightforward to serialize
  trace_t traces;
  struct qbdi_ctx  {
    trace_t* trace;
  };
  qbdi_ctx ctx{&traces};

  VM vm;
  vm.addInstrumentedModule(R2PAY_LIB);

  if (/* Improve speed */ true) {
    /*
     * Force the function sub_1038f0 to be run without instrumentation.
     * Instrumenting this function introduces a huge overhead!
     */
    static constexpr uintptr_t HEAVY_FUNCTION = 0x1038f0;
    vm.removeInstrumentedRange(base_address + HEAVY_FUNCTION, base_address + HEAVY_FUNCTION + 1);
  }

  if (/* Track memory accesses */ true) {
    /*
     * Setup memory reads & writes on the .data section
     */
    vm.recordMemoryAccess(MEMORY_READ_WRITE);
    vm.addMemRangeCB(base_address + 0x127000, base_address + 0x127000 + 0x8e000, MEMORY_READ_WRITE,
        [] (VM* vm, GPRState*, FPRState*, void* data) {
          auto ctx = reinterpret_cast<qbdi_ctx*>(data);
          /*
           * 'for' loop since on AArch64 you can have multiple reads / writes
           * in one instruction. (e.g. stp x0, x1, [sp, #128])
           */
          for (const MemoryAccess& mem_access : vm->getInstMemoryAccess()) {
            ctx->trace->push_back({
                mem_access.instAddress   - base_address,
                mem_access.accessAddress - base_address,
                mem_access.size,
            });
          }

          return VMAction::CONTINUE;
        }, &ctx);
  }

  allocateVirtualStack(vm.getGPRState(), STACK_SIZE, &fakestack);

  jbyte* ptr = nullptr;
  jbyteArray array = to_jarray(pin_amount, ptr);
  jbyteArray qbdi_encrypted_buffer;

  vm.call(
      /* ret    */ reinterpret_cast<uintptr_t*>(&qbdi_encrypted_buffer),
      /* target */ reinterpret_cast<uintptr_t>(gXftm3iswpkVgBNDUp),
      /* params */ {
        /* p_0: JNIEnv* */      reinterpret_cast<rword>(env),
        /* p_1: jobject thiz */ reinterpret_cast<rword>(nullptr),
        /* p_2: inbuffer */     reinterpret_cast<rword>(array),
                                0xF0
    }
  );
  const std::vector<uint8_t> encrypted_buffer = from_jbytes(qbdi_encrypted_buffer);
  std::string ref_str = to_hex(encrypted_buffer, /* Skip first byte */ 1);
  LOG_INFO("{} --> {}", pin_amount, ref_str);
  env->ReleaseByteArrayElements(array, ptr, 0);
  alignedFree(fakestack);

  /* Serialize trace in JSON */
  std::ofstream ofs{"/data/local/tmp/mem_trace.json"};
  ofs << json{traces}.dump();
}


std::vector<uint8_t> inject_fault(uintptr_t fault_addr, const std::string& msg, INJECTION_MODE mode,
    uint8_t value = 0x33, bool restore = true) {
  static bool DATA_RW = false;
  if (not DATA_RW) {
    mprotect(reinterpret_cast<void*>(base_address + /* .data */ 0x127000), 0x8e000, PROT_READ | PROT_WRITE);
    DATA_RW = true;
  }

  uint8_t& target_byte = *reinterpret_cast<uint8_t*>(base_address + fault_addr);
  uint8_t backup = target_byte;
  /*
   * See: https://www.cryptoexperts.com/whibox2019/slides-whibox2019/Guillaume_Vinet-fault_attack.pdf Page: 20
   */
  if (mode == INJECTION_MODE::XOR) {
    target_byte ^= value;
  }

  if (mode == INJECTION_MODE::CONST) {
    target_byte = value;
  }

  const std::vector<uint8_t> encrypted = encrypt(msg);
  if (restore) {
    target_byte = backup;
  }
  return encrypted;
}

int main(int argc, char** argv) {
  // Logger setup
  console->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
  console->flush_on(spdlog::level::err);
  console->flush_on(spdlog::level::info);
  console->flush_on(spdlog::level::warn);

  // Setup JVM
  JavaVMOption opt[2];
  opt[0].optionString = "-Djava.class.path=/data/local/tmp/re.pwnme.1.0.apk";
  opt[1].optionString = "-Djava.library.path=/data/local/tmp";

  JavaVMInitArgs args;
  args.version            = JNI_VERSION_1_6;
  args.options            = opt;
  args.nOptions           = 2;
  args.ignoreUnrecognized = JNI_FALSE;

  void* handler = dlopen("/system/lib64/libart.so", RTLD_NOW);
  if (handler == nullptr) {
    LOG_ERROR("dlopen error {}", dlerror());
    return EXIT_FAILURE;
  }

  auto JNI_CreateJavaVM_f = reinterpret_cast<decltype(JNI_CreateJavaVM)*>(dlsym(handler, "JNI_CreateJavaVM"));
  if (JNI_CreateJavaVM_f == nullptr) {
    LOG_ERROR("Unable to resolve JNI_CreateJavaVM: {}", dlerror());
    return EXIT_FAILURE;
  }

  if (JNI_CreateJavaVM_f(&jvm, &env, &args) != JNI_OK) {
    LOG_ERROR("Error while creating the JVM");
    return EXIT_FAILURE;
  }
  LOG_INFO("JVM Created!");

  // ------------------------------------------------------
  // Load the whitebox library
  // ------------------------------------------------------
  void* hdl = dlopen(R2PAY_LIB, RTLD_NOW);
  if (hdl == nullptr) {
    LOG_ERROR("Error while loading {}: {}", R2PAY_LIB, dlerror());
    return EXIT_FAILURE;
  }

  // ------------------------------------------------------
  // Resolve JNI function:
  //
  // - public native byte[] gXftm3iswpkVgBNDUp(byte[] bArr, byte b);
  // ------------------------------------------------------
  base_address = get_base_address(R2PAY_LIB);
  if (base_address == 0) {
    LOG_ERROR("Can't resolve the base address of {}", R2PAY_LIB);
    return EXIT_FAILURE;
  }

  gXftm3iswpkVgBNDUp = reinterpret_cast<gXftm3iswpkVgBNDUp_t>(
                          base_address + /* Offset of the JNI function */ 0x9B41C);
  LOG_INFO("Base address of {}: 0x{:08x}", R2PAY_LIB, base_address);

  auto start = high_resolution_clock::now();
  static constexpr char PIN_AMOUNT[] = "2345121234597234";
  // ==========================================
  // {
  //   dump_data_section("data_dump.raw");
  // }
  // ==========================================
  // {
  //   run_shim();
  // }
  // ==========================================
  // {
  //   trace_memory_accesses(PIN_AMOUNT);
  // }
  // ==========================================

  // { // Inject fault on on the memory addresses identified previously
  //   const std::vector<uint8_t> genuine_value = encrypt(PIN_AMOUNT);
  //   for (uintptr_t addr : NICE_FAULT) {
  //     const std::vector<uint8_t>& output = inject_fault(addr, PIN_AMOUNT, INJECTION_MODE::XOR);
  //     const size_t nb_errors = get_error(genuine_value, output);
  //     LOG_INFO("0x{:04x}: {} {} (#{:02d} faults)", addr, to_hex(genuine_value), to_hex(output), nb_errors);
  //   }
  // }
  // ==========================================

  // { // Now that we have nice spots to inject faults, let's record them!
  //   const std::vector<uint8_t> genuine_value = encrypt(PIN_AMOUNT);
  //   std::string hex_input = to_hex({std::begin(PIN_AMOUNT), std::end(PIN_AMOUNT) - /* skip null byte */ 1}, 0);
  //   for (uintptr_t addr : NICE_FAULT) {
  //     std::set<std::vector<uint8_t>> unique;
  //     // adb shell mkdir /data/local/tmp/wb-traces
  //     std::string trace_file = fmt::format("/data/local/tmp/wb-traces/injection-{:04x}.trace", addr);
  //     std::ofstream ofs(trace_file);
  //     for (size_t i = 0; i < 255; ++i) {
  //       if (i == 0) {
  //         // Record real values plain text / cipher text
  //         ofs << fmt::format("{} {}", hex_input, to_hex(genuine_value)) << "\n" << std::flush;
  //       }
  //       const std::vector<uint8_t>& output = inject_fault(addr, PIN_AMOUNT, INJECTION_MODE::CONST, i);
  //       const size_t nb_errors = get_error(genuine_value, output);
  //       if (nb_errors == 4 and unique.insert(output).second) {
  //         ofs << fmt::format("{} {}", hex_input, to_hex(output)) << "\n" << std::flush;
  //       }
  //     }
  //     LOG_INFO("[0x{:04x}]: {:02} faulty records", addr, unique.size());
  //   }
  // }
  // ==========================================

  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(stop - start);

  LOG_INFO("Done in {}ms!", duration.count());
  return EXIT_SUCCESS;
}
