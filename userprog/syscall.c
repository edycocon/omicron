
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
  char* comando;
  void* cmd;
  ASSERT( sizeof(sys_code) == 4 ); 
 
  
  if(!validar_puntero(f->esp + 1) || !validar_puntero(f->esp + 2) || !validar_puntero(f->esp + 3)){
    exit(-1);
  }

  if(!validar_puntero((int*)f->esp)){
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

        cmd = (void*)(*((int*)f->esp + 1));

        for(int i=0; i<sizeof(cmd); i++) {
          if(!validar_puntero(f->esp + 4 + i)){
            exit(-1);
          }
        }

        comando = (char*)(*((int*)f->esp + 1));

        for(int i=0; i<sizeof(comando); i++) {
          if(!validar_puntero(comando + i)){
            exit(-1);
          }
        }

        f->eax = exec(comando);
        break;
    case SYS_WAIT:

      if (!validar_puntero((int*)f->esp + 1)){
        exit(-1);
      }

      int pid = *((int*)f->esp + 1); 
      int retval = wait(pid);
      f->eax = (uint32_t)retval;

      break;
    case SYS_CREATE:
      
      f->eax = create(f);
      break;

    case SYS_REMOVE:
      f->eax = remove(f);
      break;
    case SYS_OPEN:

      cmd = (void*)(*((int*)f->esp + 1));

      for(int i=0; i<sizeof(cmd); i++) {
        if(!validar_puntero(f->esp + 4 + i)){
          exit(-1);
        }
      }

      nombre_archivo = (char*)(*((int*)f->esp + 1));

      for(int i=0; i<sizeof(nombre_archivo); i++) {
        if(!validar_puntero(nombre_archivo + i)){
          exit(-1);
        }
      }

      f->eax = (uint32_t)open(nombre_archivo);
      break;
    case SYS_FILESIZE:
      f->eax = filesize(f);
      break;
    case SYS_READ:
      if(!validar_puntero((int*)f->esp + 1)){
        exit(-1);
      }

      if(!validar_puntero((int*)f->esp + 2)){
        exit(-1);
      }

      if(!validar_puntero((int*)f->esp + 3)){
        exit(-1);
      }

      int fd, retvalret;
      void *buffer;
      unsigned size;

      fd = (*((int*)f->esp + 1)); 
      buffer = (char*)(*((int*)f->esp + 2));
      size = (*((int*)f->esp + 3));

      
      retvalret = read(fd, buffer, size);
      f->eax = (uint32_t) retvalret;

      break;
    case SYS_WRITE:
      if(!validar_puntero((int*)f->esp + 1)){
        exit(-1);
      }

      if(!validar_puntero((int*)f->esp + 2)){
        exit(-1);
      }

      if(!validar_puntero((int*)f->esp + 3)){
        exit(-1);
      }

      f->eax =  (uint32_t)write(f);
      break;
    case SYS_SEEK:
      seek(f);
      break;
    case SYS_TELL:
      f->eax = tell(f);
      break;
    case SYS_CLOSE:
      close(f);
      break;
    default:
      exit(-1);
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

  struct control_proceso *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->retval = status;
  }

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

  archivo_act = filesys_open(file);

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

int write (struct intr_frame *f UNUSED) {
  if(!validar_puntero((int*)f->esp + 1) || !validar_puntero((int*)f->esp + 2) || !validar_puntero((int*)f->esp + 3)){
    exit(-1);
  }

  int fd = *((int*)f->esp + 1);  
  char* buffer = (char*)(*((int*)f->esp + 2)); 
  unsigned size = (*((int*)f->esp + 3));
  int written_bytes = 0;

  lock_acquire(&filesys_lock);
  if (fd == 0){
    exit(-1);
  } else if (fd == 1) {
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

	
int wait(int pid) {
  return process_wait(pid);
}


int exec(const char *cmdline) {

  lock_acquire (&filesys_lock); 
  tid_t pid = process_execute(cmdline);
  lock_release (&filesys_lock);
  return pid;
}


bool create (struct intr_frame *f UNUSED) {
  bool result = false;
  
  if(!validar_puntero((int*)f->esp + 1) || !validar_puntero((int*)f->esp + 2)){
    exit(-1);
  }
  
  lock_acquire(&filesys_lock);
  char *nombre = (char*)(*((int*)f->esp + 1));

  if(!validar_puntero(nombre)){
    exit(-1);
  }

  unsigned initial_size = (*((int*)f->esp + 2));;

  result = filesys_create(nombre, initial_size);
  lock_release(&filesys_lock);

  return result;

}

bool remove (struct intr_frame *f UNUSED) {
  bool result = false;

  if(!validar_puntero((int*)f->esp + 1)){
    exit(-1);
  }

  lock_acquire(&filesys_lock);
  char *nombre = (char*)(*((int*)f->esp + 1));

  if(!validar_puntero(nombre)){
    exit(-1);
  }

  result = filesys_remove(nombre);
  lock_release(&filesys_lock);

  return result;

}

int filesize (struct intr_frame *f UNUSED) {
  if(!validar_puntero((int*)f->esp + 1)){
    exit(-1);
  }

  int fd = *((int*)f->esp + 1); 
  int size = 0;

  struct stArchivo *archivo_st = obtener_Archivo(fd);

  if (archivo_st == NULL) {
    lock_release (&filesys_lock);
    return 0;
  }

  struct file *archivo = archivo_st->archivo;
  
  lock_acquire(&filesys_lock);
  size = file_length(archivo);
  lock_release(&filesys_lock);

  return size;
}

void close (struct intr_frame *f UNUSED) {
  struct file* archivo_tmp;
  if(!validar_puntero((int*)f->esp + 1)){
    exit(-1);
  }
  
  int fd = *((int*)f->esp + 1);

  lock_acquire (&filesys_lock);
  struct stArchivo* archivo_st = obtener_Archivo(fd);

  if(archivo_st && archivo_st->archivo) {
    file_close(archivo_st->archivo);
    list_remove(&(archivo_st->elem));
    palloc_free_page(archivo_st);
  }
  lock_release (&filesys_lock);
}

/* Referencia Manual de pintos seccion 3.1.5*/

static int32_t
get_user (const uint8_t *uaddr) {

  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Referencia  Manual de pintos seccion 3.1.5*/
static bool
put_user (uint8_t *udst, uint8_t byte) {
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;

  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


static void
validarmemoriabyte (const uint8_t *uaddr) {
 
  if(get_user (uaddr) == -1){
    if (lock_held_by_current_thread(&filesys_lock)){
      lock_release (&filesys_lock);
    }
    exit(-1);
  }
}



int read(int fd, void *buffer, unsigned size){

    validarmemoriabyte((const uint8_t*) buffer);
    validarmemoriabyte((const uint8_t*) buffer + size - 1);



    lock_acquire (&filesys_lock);
    int retval;


    if(fd == 0) { 
      unsigned i;
      for(i = 0; i < size; ++i) {

        if(! put_user(buffer + i, input_getc()) ) {
          lock_release (&filesys_lock);
          exit(-1); 
        }
      }
      retval = size;
    }else{ 

      struct stArchivo* file_d = obtener_Archivo(fd);

      if(file_d && file_d->archivo) {

        retval = file_read(file_d->archivo, buffer, size);
      
      }
      else {
        retval = -1;
      }
    }

    lock_release (&filesys_lock);
    return retval;
}


void seek (struct intr_frame *f UNUSED) {
  if(!validar_puntero((int*)f->esp + 1)){
    exit(-1);
  }

  if(!validar_puntero((int*)f->esp + 2)){
    exit(-1);
  }

  int fd = (int*)f->esp + 1;
  unsigned position = (int*)f->esp + 2;

  lock_acquire (&filesys_lock);
  struct stArchivo* archivo_st = obtener_Archivo(fd);

  if(archivo_st && archivo_st->archivo) {
    file_seek(archivo_st->archivo, position);
  }
  else {
    lock_release (&filesys_lock);
    return;
  }

  lock_release (&filesys_lock);
}

unsigned tell (struct intr_frame *f UNUSED) {
  unsigned result;
  if(!validar_puntero((int*)f->esp + 1)){
    exit(-1);
  }

  int fd = (int*)f->esp + 1;

  lock_acquire (&filesys_lock);
  struct stArchivo* archivo_st = obtener_Archivo(fd);
  
  result = file_tell(archivo_st->archivo);
  lock_release(&filesys_lock);
  
  return result;
}
