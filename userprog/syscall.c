
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

struct lock filesys_lock;

struct lock filesys_lock;

struct stArchivo {
  int fd;
  struct file* archivo;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sys_code;
  char* nombre_archivo;
  ASSERT( sizeof(sys_code) == 4 ); 
 
  if(!validar_puntero(f->esp) || !validar_puntero(f->esp + 1) || !validar_puntero(f->esp + 2) || !validar_puntero(f->esp + 3)){
    exit(-1);
  }

  sys_code = *(int*)f->esp;

  switch (sys_code) {
    case SYS_HALT:
      shutdown_power_off();
      PANIC ("executed an unreachable statement");
      break;
    case SYS_EXIT:

      if(!validar_puntero((int*)f->esp + 1)){
        exit(-1);
      }

      int status = *((int*)f->esp + 1);

      exit(status);
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
      if(!validar_puntero((int*)f->esp + 1)){
        exit(-1);
      }
      nombre_archivo = (char*)(*((int*)f->esp + 1));
      f->eax = (uint32_t)open(nombre_archivo);
      break;
    case SYS_FILESIZE:
      /* code */
      break;
    case SYS_READ:
      /* code */
      break;
    case SYS_WRITE:
      f->eax =  (uint32_t)sys_write(f);
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

  //thread_exit ();
}

bool validar_puntero(void *puntero) {
  uint32_t *pagina_usr = thread_current()->pagedir; 

  if (puntero == NULL || !is_user_vaddr(puntero)) {
    return false;
  }
  
  if (pagedir_get_page(pagina_usr, puntero) == NULL) {
    return false;;
  }

  return true;
}

void exit(int status) {

  struct thread *tActual = thread_current();

  printf("%s: exit(%d)\n", tActual->name, status);

  thread_exit ();
}

int open(const char* file) {
  struct file* archivo_act;
  struct stArchivo* archivo_tmp = palloc_get_page(0);

  if (archivo_tmp == NULL) {
    palloc_free_page (archivo_tmp);
    return -1;
  }

  lock_acquire (&filesys_lock);

  archivo_act = file_open(file);

  if (archivo_act == NULL) {
    palloc_free_page (archivo_tmp);
    lock_release (&filesys_lock);
    return -1;
  }

  archivo_tmp->archivo = archivo_act;
  archivo_tmp->fd = thread_current()->max_fd++;

  list_push_back(&(thread_current()->archivos), &(archivo_tmp->elem));

  lock_release (&filesys_lock);

  return archivo_tmp->fd;
}

int sys_write (struct intr_frame *f UNUSED) {
  int fd = *((int*)f->esp + 1);  
  char* buffer = (char*)(*((int*)f->esp + 2)); 
  unsigned size = (*((int*)f->esp + 3));
  int written_bytes = 0;

  lock_acquire(&filesys_lock);

  if (fd == 1){
    putbuf(buffer, size);
    lock_release (&filesys_lock);
    return size;

  } else {
    struct stArchivo *archivo = obtener_Archivo(fd);

    if (archivo == NULL) {
      lock_release (&filesys_lock);
      return 0;
    }
  
    written_bytes = (int)file_write(archivo->archivo, buffer, size);
    
  }

  lock_release (&filesys_lock);

  return written_bytes;
}

struct stArchivo* obtener_Archivo(int fd) {
  struct thread *t = thread_current();
  struct list_elem *e;

  if(fd <3){
    return NULL;
  }

  if(!list_empty(&t->archivos)){
    for(e = list_begin(&t->archivos); e != list_end(&t->archivos); e = list_next(e)) {
      struct stArchivo *archivo_temp = list_entry(e, struct stArchivo, elem);

      if(archivo_temp->fd == fd) {
        return archivo_temp;
      }
    }
  }

  return NULL;
}