#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/interrupt.h"


void syscall_init (void);

bool validar_puntero (void *pointer);
void exit (int status);
int open(const char* file);
struct stArchivo* obtener_Archivo(int fd);

int write (struct intr_frame *f);
bool create (struct intr_frame *f);
bool remove (struct intr_frame *f);
int filesize (struct intr_frame *f);
void close (struct intr_frame *f);

#endif /* userprog/syscall.h */
