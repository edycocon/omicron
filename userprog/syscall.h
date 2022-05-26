#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/interrupt.h"

void syscall_init (void);

void validar_puntero (void *pointer);
void exit (int status);
int open(const char* file);
struct stArchivo* obtener_Archivo(int fd);
int sys_write (struct intr_frame *f);

#endif /* userprog/syscall.h */
