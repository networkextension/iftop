/* hash table */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include "proc_hash.h"
#include "hash.h"
#include "iftop.h"

// Deliberately not a power of 2 or 10
#define hash_table_size 123

typedef struct proc_list proc_list;

struct proc_list {
  ip_process* this;
  proc_list* next;
};

static const char *const re_port_num = "^(udp|tcp)[[:space:]]*[[:alpha:]-]+[[:space:]]+[[:digit:]]+[[:space:]]+"
                                        "[[:digit:]]+[[:space:]]+"
                                        "(([[:digit:]]+\\.[[:digit:]]+\\.[[:digit:]]+\\.[[:digit:]]+"
                                        "(%[[:alnum:]]+)?)|(\\[([[:digit:]]*:)+[[:digit:]]*\\]))"
                                        ":([[:digit:]]+)"; // \7 is port
static const char *const re_proc_name_pid = "users:\\(\\(\"([[:alpha:]-]+)\",pid=([[:digit:]]+)"; // \1 is procname, \2 is pid

regex_t rege_port_num;
regex_t rege_proc_name_pid;

int proc_hash_compare(void* a, void* b) {
    ip_process* aa = (ip_process*)a;
    ip_process* bb = (ip_process*)b;
    return (aa->port == bb->port);
}

int proc_hash_hash(void* key) {
    ip_process* pkey = (ip_process*)key;
    return pkey->port % hash_table_size;
}

void* proc_hash_copy_key(void* orig) {
    int* copy;
    copy = xmalloc(sizeof *copy);
    *copy = *(int*)orig;
    return copy;
}

void proc_hash_delete_key(void* key) {
    free(key);
}

void child_exec(int* pipe_fd, int option) {
    close(pipe_fd[0]);    // close reading end in the child
    dup2(pipe_fd[1], 1);  // send stdout to the pipe
    dup2(pipe_fd[1], 2);  // send stderr to the pipe
    close(pipe_fd[1]);    // this descriptor is no longer needed
    switch (option) {
    case 2:
      execlp("ss", "-O", "-H", "-l", "-n", "-t", "-u", "-p", (char *)NULL);
      break;
    case 1:
      execlp("ss", "-O", "-H", "-n", "-t", "-u", "-p", (char *)NULL);
      break;
    case 0:
    default:
      execlp("ss", "-O", "-H", "-a", "-n", "-t", "-u", "-p", (char *)NULL);
      break;
    }
}

proc_list* proc_parse_parent(int *pipefd) {
  proc_list* list = malloc(sizeof(proc_list));
  proc_list* ret = list;
  list->this = malloc(sizeof(ip_process));
  list->this->name = strdup("myprog");
  list->this->port = 45678;
  list->next = NULL;

  regmatch_t pmatch[10];
  regoff_t len, shift;
  int buf_len = 65536;
  char buffer[buf_len];
  uint16_t tmp_port;
  char* tmp_sport;
  char* tmp_name;
  close(pipefd[1]);  // close the write end of the pipe in the parent
  while (read(pipefd[0], buffer, sizeof(buffer)) != 0)
  {
    // parse results from child to match process names with port numbers
    const char *c = buffer;
    while (1) {
      if (regexec(&rege_port_num, c, sizeof(pmatch) / sizeof(pmatch[0]), pmatch, 0)) {
        break;
      }
      shift = pmatch[0].rm_eo;
      len = pmatch[7].rm_eo - pmatch[7].rm_so;
      tmp_sport = strndup(c + pmatch[7].rm_so, len);
      tmp_port = atoi(tmp_sport);
      if (regexec(&rege_proc_name_pid, c, sizeof(pmatch) / sizeof(pmatch[0]), pmatch, 0)) {
        c += shift;
        continue;
      }
      len = pmatch[1].rm_eo - pmatch[1].rm_so;
      tmp_name = strndup(c + pmatch[1].rm_so, len);
      // no need to retrieve pid
      list->this = malloc(sizeof(ip_process));
      list->this->port = tmp_port;
      list->this->name = tmp_name;
      list->next = malloc(sizeof(proc_list));
      list = list->next;
      list->this = NULL;
      list->next = NULL;
      c += pmatch[0].rm_eo;
    }
    memset(buffer, 0, sizeof(buffer));
  }
  return ret;
}

proc_list* proc_parse_fork() {
  int pipefd[2];
  pipe(pipefd);
  if (fork() == 0) { // child
    child_exec(pipefd, 0); // "-a" flag
  }
  return proc_parse_parent(pipefd);
}


// return value == true for 'more items in list'
bool proc_result_free(proc_list** procs) {
  if ((*procs)->next == NULL) {
    free(*procs);
    return false;
  }
  proc_list* rem = *procs;
  *procs = (*procs)->next;
  free(rem);
  return true;
}

void proc_hash_init_refresh(hash_type* sh, bool refresh) {
  proc_list* processes;
  ip_process* process;
  void* rec;
  if (!refresh) {
    regcomp(&rege_port_num, re_port_num, REG_NEWLINE | REG_EXTENDED);
    regcomp(&rege_proc_name_pid, re_proc_name_pid, REG_NEWLINE | REG_EXTENDED);
  }
  processes = proc_parse_fork();
  while (processes != NULL && processes->this != NULL) {
    process = processes->this;
    if (refresh && hash_find(sh, process, &rec) == HASH_STATUS_OK) {
      if (strcmp((char *)rec, process->name) == 0) {
        if (!proc_result_free(&processes)) {
          break;
        }
        continue;
      } else {
        hash_delete(sh, process);
      }
    }
    hash_insert(sh, process, strdup(process->name));
    if (!proc_result_free(&processes)) {
      break;
    }
  }
}

void proc_hash_not_found(void* vp_process_hash) {
  static bool recursive;
  static int n_times;
  hash_type* process_hash = (hash_type*)vp_process_hash;
  if (!recursive && ++n_times >= 20) {
    n_times = 0;
    recursive = true;
    proc_hash_init_refresh(process_hash, true);
    recursive = false;
  }
}

/*
 * Allocate and return a hash
 */
hash_type* proc_hash_create() {
    hash_type* hash_table;
    hash_table = xcalloc(hash_table_size, sizeof *hash_table);
    hash_table->size = hash_table_size;
    hash_table->compare = &proc_hash_compare;
    hash_table->hash = &proc_hash_hash;
    hash_table->delete_key = &proc_hash_delete_key;
    hash_table->copy_key = &proc_hash_copy_key;
    hash_table->not_found_callback = proc_hash_not_found;
    hash_initialise(hash_table);
    return hash_table;
}
