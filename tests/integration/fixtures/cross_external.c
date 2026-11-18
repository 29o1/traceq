#include <stdint.h>
typedef void (*Callback)(uint64_t,volatile uint64_t*);
// Deliberately in a separate, excluded image. Same-value writes must still
// leave provenance unknown; a later observed load cannot identify the writer.
uint64_t cross_external(uint64_t seed,volatile uint64_t* buffer,uint64_t mode,Callback callback) {
    if(mode==3)return seed+7; // Explicit no-write control.
    if(mode==2 && callback)callback(seed,buffer);
    buffer[0]=mode==0?seed:seed^(mode==2?0xa5:0x5a);
    return seed+7;
}
