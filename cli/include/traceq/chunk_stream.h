#pragma once
#include <traceq/write_stream.h>
#include <algorithm>
#include <array>
#include <vector>

// Lossless transport for the same logical Events. Each block restarts its
// sequence/PC delta predictors; register observations still span blocks.
namespace traceq::chunks {
using writes::Event;
constexpr char MAGIC[8]={'G','T','S','C','0','0','1',0};
constexpr char BLOCK_MAGIC[8]={'G','T','B','L','0','0','1',0};
constexpr size_t RECORDS=1024, MAX_RECORD=61, CAPACITY=RECORDS*64+8;
inline void put32(unsigned char* p,uint32_t v){
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(p,&v,sizeof v);
#else
    for(unsigned i=0;i<4;++i)p[i]=uint8_t(v>>(8*i));
#endif
}
inline uint32_t get32(const unsigned char* p){uint32_t v=0;for(unsigned i=0;i<4;++i)v|=uint32_t(p[i])<<(8*i);return v;}
inline uint64_t zigzag(uint64_t d){return (d<<1)^(0-(d>>63));}
inline uint64_t unzigzag(uint64_t d){return (d>>1)^(0-(d&1));}
inline unsigned width(uint64_t v){return v?(64-__builtin_clzll(v)+7)/8:0;}

// No allocation, no dependencies. CAPACITY includes eight scratch bytes for
// overlapping full-width stores; only the returned byte count is committed.
__attribute__((noinline)) inline size_t encode(const Event* events,size_t count,unsigned char* out,size_t capacity) {
    if(count>RECORDS || capacity<count*MAX_RECORD+8)return 0;
    size_t pos=0;uint64_t seq=0,pc=0;
    for(size_t i=0;i<count;++i) {
        const auto& e=events[i];if(e.kind>255)return 0;
        uint64_t v[]={zigzag(e.seq-seq),zigzag(e.pc-pc),e.address,e.size,e.low,e.high,e.detail};
        seq=e.seq;pc=e.pc;out[pos++]=uint8_t(e.kind);size_t header=pos;pos+=4;uint32_t widths=0;
        for(unsigned j=0;j<7;++j){unsigned n=width(v[j]);widths|=n<<(4*j);writes::put64(out+pos,v[j]);pos+=n;}
        put32(out+header,widths);
    }
    return pos;
}
inline bool decode(const unsigned char* bytes,size_t size,size_t count,std::vector<Event>& out) {
    if(!count || count>RECORDS || size>count*MAX_RECORD)return false;
    size_t pos=0;uint64_t seq=0,pc=0;out.clear();out.reserve(count);
    for(size_t i=0;i<count;++i) {
        if(size-pos<5)return false;
        uint64_t kind=bytes[pos++],v[7]{};uint32_t widths=get32(bytes+pos);pos+=4;
        if(widths>>28)return false;
        for(unsigned j=0;j<7;++j){unsigned n=(widths>>(4*j))&15;if(n>8 || n>size-pos)return false;
            for(unsigned k=0;k<n;++k)v[j]|=uint64_t(bytes[pos++])<<(8*k);}
        seq+=unzigzag(v[0]);pc+=unzigzag(v[1]);
        out.push_back({kind,seq,pc,v[2],v[3],v[4],v[5],v[6]});
    }
    return pos==size;
}
inline bool write_header(FILE* file,const writes::Header& h) {
    unsigned char b[writes::FRAME_SIZE]{};memcpy(b,MAGIC,8);
    const uint64_t values[]={h.code_base,h.code_size,h.data_base,h.data_size,h.thread_id,h.profile,writes::FRAME_SIZE};
    for(unsigned i=0;i<7;++i)writes::put64(b+8+i*8,values[i]);
    return fwrite(b,1,sizeof b,file)==sizeof b;
}

// Shared input adapter lets queries consume both transports without making an
// expanded temporary file. The semantic reader retains all existing checks.
class Input {
    FILE* file_;bool chunked_=false;std::vector<unsigned char> bytes_;
    std::vector<Event> events_;size_t index_=0;
public:
    explicit Input(FILE* file):file_(file){}
    bool header(unsigned char* b) {
        if(fread(b,1,writes::FRAME_SIZE,file_)!=writes::FRAME_SIZE)return false;
        chunked_=memcmp(b,MAGIC,8)==0;
        return chunked_ || memcmp(b,writes::MAGIC,8)==0;
    }
    bool next(Event& event) {
        if(!chunked_){unsigned char b[writes::FRAME_SIZE];if(fread(b,1,sizeof b,file_)!=sizeof b)return false;event=writes::decode_event(b);return true;}
        if(index_==events_.size()) {
            unsigned char head[16];if(fread(head,1,sizeof head,file_)!=sizeof head || memcmp(head,BLOCK_MAGIC,8))return false;
            size_t count=get32(head+8),size=get32(head+12);
            if(!count || count>RECORDS || size>count*MAX_RECORD)return false;
            bytes_.resize(size);if(fread(bytes_.data(),1,size,file_)!=size || !decode(bytes_.data(),size,count,events_))return false;
            index_=0;
        }
        event=events_[index_++];return true;
    }
    bool finished(){return (!chunked_ || index_==events_.size()) && fgetc(file_)==EOF && !ferror(file_);}
    bool chunked()const{return chunked_;}
};
}
