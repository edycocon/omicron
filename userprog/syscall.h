#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

void syscall_init (void);

bool validar_puntero (void *pointer);
void exit (int status);
int open(const char* file);

#endif /* userprog/syscall.h */
