#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

#include "nyx.h"

// If we're keeping track of coverage for both the target and the scenario
// processes, then we use a single large map to combine the coverage:
//
// [ ... TARGET MAP ... | ... SCENARIO MAP ... ]
//
// The map is shared with the target via the __AFL_SHM_ID env variable and the
// scenario's __afl_area_ptr is set to the map pointer offset by
// TARGET_MAP_SIZE.
__attribute__((weak)) extern uint8_t *__afl_area_ptr;
__attribute__((weak)) extern uint32_t __afl_map_size;

static uint8_t *trace_buffer = NULL;
static size_t trace_buffer_size = 0;

/** Initiliaze the nyx agent and return the maximum size for generated fuzz
 * inputs.
 *
 * Sets the __AFL_SHM_ID env variable to the shmid of the trace buffer. */
size_t nyx_init() {
  static int done = 0;
  (void)__builtin_expect(done, 0);
  done = 1;

  host_config_t host_config;
  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

  if (host_config.host_magic != NYX_HOST_MAGIC) {
    habort("Error: NYX_HOST_MAGIC not found in host configuration - You are "
           "probably using an outdated version of QEMU-Nyx...");
  }

  if (host_config.host_version != NYX_HOST_VERSION) {
    habort("Error: NYX_HOST_VERSION not found in host configuration - You are "
           "probably using an outdated version of QEMU-Nyx...");
  }

  hprintf("[capablities] host_config.bitmap_size: 0x%" PRIx64 "\n",
          host_config.bitmap_size);
  hprintf("[capablities] host_config.ijon_bitmap_size: 0x%" PRIx64 "\n",
          host_config.ijon_bitmap_size);
  hprintf("[capablities] host_config.payload_buffer_size: 0x%" PRIx64 "x\n",
          host_config.payload_buffer_size);

  agent_config_t agent_config = {0};
#ifdef TARGET_MAP_SIZE
  agent_config.coverage_bitmap_size = TARGET_MAP_SIZE;
  hprintf("[init] using TARGET_MAP_SIZE: %d\n",
          agent_config.coverage_bitmap_size);
  if (&__afl_area_ptr) {
    hprintf("[init] scenario was build with afl instrumentation, extending the "
            "map by %d edges\n",
            __afl_map_size);
    agent_config.coverage_bitmap_size += __afl_map_size;
  } else {
    hprintf("[init] scenario not compiled with afl instrumentation\n");
  }
#else
  hprintf("[warn] TARGET_MAP_SIZE not set, using host supplied size: %d\n",
          host_config.bitmap_size);
  agent_config.coverage_bitmap_size = host_config.bitmap_size;
#endif

  key_t key = ftok("/tmp", 'T'); // 'T' for trace
  int shmid = shmget(key, agent_config.coverage_bitmap_size, IPC_CREAT | 0666);
  if (shmid == -1) {
    habort("Error: Failed to create shared memory segment for trace buffer");
  }

  // Write trace buffer shmemid to __AFL_SHM_ID env variable
  char shmid_str[16];
  memset(shmid_str, 0, sizeof(shmid_str));
  snprintf(shmid_str, sizeof(shmid_str), "%d", shmid);
  setenv("__AFL_SHM_ID", shmid_str, 1);
  char map_size_str[16];
  memset(map_size_str, 0, sizeof(map_size_str));
  snprintf(map_size_str, sizeof(map_size_str), "%d",
           agent_config.coverage_bitmap_size);
  setenv("AFL_MAP_SIZE", map_size_str, 1);

  trace_buffer = (uint8_t *)shmat(shmid, NULL, 0);
  if (trace_buffer == (void *)-1) {
    habort("Error: Failed to attach to shared memory segment for trace buffer");
  }

  trace_buffer_size = agent_config.coverage_bitmap_size;
  memset(trace_buffer, 0, trace_buffer_size);

  agent_config.agent_magic = NYX_AGENT_MAGIC;
  agent_config.agent_version = NYX_AGENT_VERSION;
  agent_config.agent_timeout_detection = (uint8_t)0;
  agent_config.agent_tracing = (uint8_t)1;
  agent_config.trace_buffer_vaddr = (uintptr_t)trace_buffer;
  agent_config.agent_ijon_tracing = 0;
  agent_config.ijon_trace_buffer_vaddr = (uintptr_t)NULL;
  agent_config.agent_non_reload_mode = (uint8_t)1;

  kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

  return host_config.payload_buffer_size;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/** Dump contents of `data` to a file on the host named `file_name` */
void nyx_dump_file_to_host(const char *file_name, size_t file_name_len,
                           const uint8_t *data, size_t len) {
  char file_name_array[256] = {0};
  memset(file_name_array, 0, 256);
  strncpy(file_name_array, file_name,
          MIN(file_name_len, sizeof(file_name_array)));
  file_name_array[255] = 0;

  kafl_dump_file_t file_obj = {0};
  file_obj.file_name_str_ptr = (uintptr_t)file_name_array;
  file_obj.append = 1;
  file_obj.bytes = len;
  file_obj.data_ptr = (uintptr_t)data;
  kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));
}

/** Copy the next fuzz input into `data` and return the new size of the input.
 *
 * Note: This will take the snapshot on the first call. */
size_t nyx_get_fuzz_input(const uint8_t *data, size_t max_size) {
  kAFL_payload *payload_buffer = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  mlock(payload_buffer, max_size);
  memset(payload_buffer, 0, max_size);

  // Register payload buffer
  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
  hprintf("[init] payload buffer is mapped at %p (size: 0x%lx)\n",
          payload_buffer, max_size);

  // Reset trace buffer
  memset(trace_buffer, 0, trace_buffer_size);

#ifdef TARGET_MAP_SIZE
  if (&__afl_area_ptr) {
    __afl_area_ptr = trace_buffer + TARGET_MAP_SIZE;
  }
#endif

  // Take snapshot
  hprintf("[init] taking snapshot\n");
  kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
  kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

  trace_buffer[0] = 1;

  // Copy payload buffer into data
  memcpy((void *)data, payload_buffer->data, payload_buffer->size);

  return payload_buffer->size;
}

/** Resets the coverage bitmap and then resets the vm to the snapshot state. */
void nyx_skip() {
  // TODO: this is racy, we should stop the target from writing to the trace
  // buffer before resetting it.
  memset(trace_buffer, 0, trace_buffer_size);
  trace_buffer[0] = 1;
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}

/** Resets the vm to the snapshot state. */
void nyx_release() { kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0); }

/** Indicate a crash (including a message) to the fuzzer. */
void nyx_fail(const char *message) {
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)message);
}
