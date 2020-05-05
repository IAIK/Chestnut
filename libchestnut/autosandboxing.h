#ifndef ASB_AUTOSANDBOXING_H
#define ASB_AUTOSANDBOXING_H

#include <stdint.h>

#define STRINGIFY(x) #x
#define JOIN(a, b) a##b
#define UNIQUE_NOTE(n) JOIN(_note, n)

#define ELF_NOTE(section_name, note_name, note_type, note_desc)    \
  __attribute__((used, section(section_name))) static const struct \
  {                                                                \
    struct                                                         \
    {                                                              \
      uint32_t n_namesz, n_descsz, n_type;                         \
    } hdr;                                                         \
    char name[sizeof(note_name)];                                  \
    _Alignas(4) struct                                             \
    {                                                              \
      char content[sizeof(note_desc)];                             \
    } desc;                                                        \
  } UNIQUE_NOTE(__COUNTER__) = {                                   \
      .hdr = {                                                     \
          .n_namesz = sizeof(note_name),                           \
          .n_descsz = sizeof(note_desc),                           \
          .n_type = note_type,                                     \
      },                                                           \
      .name = note_name,                                           \
      .desc = {.content = note_desc}                               \
  };

/* Manually create a note that contains syscall numbers for a specific function.
 */
#define SYSCALL_NOTE_JSON(func, functype, funcsyscalls)                     \
  "{\"addresses_taken\":[],\"functions\":[{\"name\":\"" STRINGIFY(func)     \
  "\",\"type\":\"" functype "\",\"syscall_numbers\":[" funcsyscalls "]}]}"
#define SYSCALL_NOTE(func, functype, funcsyscalls) \
 ELF_NOTE(".note.callhierarchy", "NOTE", 0x400, SYSCALL_NOTE_JSON(func, functype, funcsyscalls))

#define CALL_NOTE_JSON(func, functype, funcsyscalls, call_targets, indirect)  \
  "{\"addresses_taken\":[],\"functions\":[{\"name\":\"" STRINGIFY(func)       \
  "\",\"type\":\"" functype "\",\"syscall_numbers\":[" funcsyscalls "],"      \
  "\"call_targets\":[" call_targets "],"                                      \
  "\"indirect_call_types\": [" indirect "]}]}"
#define CALL_NOTE(func, functype, funcsyscalls, call_targets, indirect) \
 ELF_NOTE(".note.callhierarchy", "NOTE", 0x400, CALL_NOTE_JSON(func, functype, funcsyscalls, call_targets, indirect))

#endif /* ASB_AUTOSANDBOXING_H */
