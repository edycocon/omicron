
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <stdbool.h>
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "list.h"

static void syscall_handler (struct intr_frame *);

struct stArchivo {
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
    exit(-1);
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
    case SYS_FILESIZE:
      /* code */
      break;
    case SYS_READ:
      /* code */
      break;
    case SYS_WRITE:
      f->eax = write(f);
      break;
    case SYS_SEEK:
      /* code */
      break;
    case SYS_TELL:
      /* code */
      break;
    case SYS_CLOSE:
      /* code */
      break;
    
    default:
      break;
  }

  thread_exit ();
}

void validar_puntero(void *puntero) {
  uint32_t *pagina_usr = thread_current()->pagedir; 

  if (!is_user_vaddr(puntero) || puntero == NULL) {
    exit(-1);
  }
  
  if (pagedir_get_page(pagina_usr, puntero) == NULL) {
    exit(-1);
  }
}

void exit(int status) {
  if (status != -1) {
    validar_puntero(status);
  }

  struct thread *tActual = thread_current();

  printf("%s: exit(%d)\n", tActual->name, status);

  thread_exit ();
}

int open(const char* file) {

  if (!validar_puntero(file)) {
    exit(-1);
  }

  struct file* archivo_act;
  struct stArchivo* archivo_tmp = palloc_get_page(0);

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

int write (struct intr_frame *f UNUSED) {
  validar_puntero((int*)f->esp + 1);
  validar_puntero((int*)f->esp + 2);
  validar_puntero((int*)f->esp + 3);

  int fd = *((int*)f->esp + 1);  
  char* buffer = (char*)(*((int*)f->esp + 2)); 
  unsigned size = (*((int*)f->esp + 3));

  //Que hago cuando venga STDIN_FILENO
  if (fd == STDOUT_FILENO){
    putbuf(buffer, size);
    return size;

  } else {
    struct stArchivo archivo = obtener_Archivo(fd);
    int written_bytes = 0;

    if (archivo == NULL) {
      return 0;
    }

    written_bytes = file_write(archivo->archivo, buffer, size);

    return written_bytes;
  }
}

struct stArchivo obtener_Archivo(int fd, enum fd_search_filter flag) {
  struct thread *t = thread_current();
  struct list_elem *e;

  for(e = list_begin(&t->archivos); e != list_end(&t->archivos); e = list_next(e)) {
    struct stArchivo *archivo_temp = list_entry(e, struct stArchivo, elem);

    if(archivo_temp->fd == fd) {
      return archivo_temp;
    }
  }

  return NULL;
}
