#include <string.h>  /* strcpy */
#include <stdlib.h>  /* malloc */
#include <stdio.h>   /* printf */
#include "uthash.h"
 
typedef struct hashTableChrInt {
    char key[500];                    /* key */
    int value;             
    UT_hash_handle hh;         /* makes this structure hashable */
}hashTableChrInt;
 
 
void add_read( hashTableChrInt * reads,  char *read) {
    hashTableChrInt *s = NULL;;
    int x =10;
  
    s = ( hashTableChrInt*)malloc(sizeof( hashTableChrInt));
    strcpy(s->key, read);
    s->value = x;
    HASH_ADD_STR( reads, key, s );
     
 
}
 
int main() {
    char read[] = "Robert";
    char name[]="betty";
    hashTableChrInt *s, *tmp, *reads = NULL;
      
    add_read(reads,read);
    add_read(reads,name);
 
 
    HASH_FIND_STR( reads, "betty", s);
    if (s) printf("betty's id is %d\n", s->value);
 
    /* free the hash table contents */
    HASH_ITER(hh, reads, s, tmp) {
        HASH_DEL(reads, s);
        free(s);
    }
    return 0;
}
