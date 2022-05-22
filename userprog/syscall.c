
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <stdbool.h>
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

struct archivos {
  int fd;
  struct file* archivo;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sys_code = *(int*)f->esp;
  char* nombre_archivo;

  if (!validar_puntero(f->esp))
  {
    exit(13);
  }

  switch (sys_code) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      exit(sys_code);
    break;
      case SYS_EXEC:
      /* code */
      break;
    case SYS_WAIT:
      /* code */
      break;
    case SYS_CREATE:
      /* code */
      break;
    case SYS_REMOVE:
      /* code */
      break;
    case SYS_OPEN:
      nombre_archivo = (char*)(*((int*)f->esp + 1));
      f->eax = open(nombre_archivo);
      break;
    
    default:
      break;
  }

  thread_exit ();
}

bool validar_puntero(void *puntero) {
  uint32_t *pagina_usr = thread_current()->pagedir; 

  if (!is_user_vaddr(puntero) || puntero == NULL) {
    return false;
  }
  
  if (pagedir_get_page(pagina_usr, puntero) == NULL) {
    return false;
  }
  
  return true;
}

void exit(int status) {
  if (!validar_puntero(status)) {
    status = 13;
  }

  struct thread *tActual = thread_current();

  printf("%s: exit(%d)\n", tActual->name, status);

  thread_exit ();
}

int open(const char* file) {

  if (!validar_puntero(file)) {
    exit(13);
  }

  struct file* archivo_act;
  struct archivos* archivo_tmp = palloc_get_page(0);

  if (archivo_tmp == NULL) {
    return -1;
  }

  archivo_act = file_open(file);

  if (archivo_act == NULL) {
    return -1;
  }

  archivo_tmp->archivo = archivo_act;
  archivo_tmp->fd = thread_current()->max_fd++;

  list_push_back(&(thread_current()->archivos), &(archivo_tmp->elem));

  return -1;
}
