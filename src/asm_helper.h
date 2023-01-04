#pragma once

namespace zhook {

// jmpcode: 0xff, 0x25, 0x00, 0x00, 0x00, 0x00
// FAR_JMP_CODE_LEN = sizeof(jmpcode) + sizeof(long)

#if __WORDSIZE == 64
#define FAR_JMP_CODE_LEN 14
#else
#define FAR_JMP_CODE_LEN 10
#endif

}  // namespace zhook
