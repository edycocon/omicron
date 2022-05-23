#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

void syscall_init (void);

bool validar_puntero (void *pointer);
void exit (int status);
int open(const char* file);
struct stArchivo obtener_Archivo(int fd, enum fd_search_filter flag);
int write (struct intr_frame *f);

#endif /* userprog/syscall.h */
