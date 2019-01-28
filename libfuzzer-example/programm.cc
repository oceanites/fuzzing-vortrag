#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 0 && data[0] == 'F')
    if (size > 1 && data[1] == 'u')
       if (size > 2 && data[2] == 'z')
           if (size > 3 && data[3] == 'z')
               if (size > 4 && data[4] == '!')
                   __builtin_trap();
  return 0;
}

