// Packed-field decoding must be exact and bounded, including at a guard page.
#include <traceq/chunk_stream.h>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <stdexcept>
#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#endif
using traceq::writes::Event;
static void require(bool ok){if(!ok)throw std::runtime_error("chunk decode regression");}
static bool same(const std::vector<Event>& a,const std::vector<Event>& b){
    if(a.size()!=b.size())return false;
    for(size_t i=0;i<a.size();++i){const auto&x=a[i];const auto&y=b[i];
        if(x.kind!=y.kind || x.seq!=y.seq || x.pc!=y.pc || x.address!=y.address ||
           x.size!=y.size || x.low!=y.low || x.high!=y.high || x.detail!=y.detail)return false;}
    return true;
}
// Deliberately byte based reference: it does not perform a word load or call
// production extraction helpers, so it also works on unaligned short tails.
static bool reference(const unsigned char* bytes,size_t size,size_t count,std::vector<Event>& out){
    if(!count || count>1024 || size>count*61)return false;
    size_t pos=0;uint64_t seq=0,pc=0;out.clear();
    for(size_t i=0;i<count;++i){
        if(size-pos<5)return false;uint64_t kind=bytes[pos++],v[7]{};uint32_t widths=0;
        for(unsigned k=0;k<4;++k)widths|=uint32_t(bytes[pos++])<<(k*8);
        if(widths>>28)return false;
        for(unsigned j=0;j<7;++j){unsigned n=(widths>>(j*4))&15;if(n>8 || n>size-pos)return false;
            for(unsigned k=0;k<n;++k)v[j]+=uint64_t(bytes[pos++])<<(k*8);}
        auto delta=[](uint64_t n){return (n>>1)^uint64_t(0-(n&1));};seq+=delta(v[0]);pc+=delta(v[1]);
        out.push_back({kind,seq,pc,v[2],v[3],v[4],v[5],v[6]});
    }
    return pos==size;
}
static unsigned checked=0;
static void check(const unsigned char* data,size_t size,size_t count){
    std::vector<Event> a,b;bool expected=reference(data,size,count,a),got=traceq::chunks::decode(data,size,count,b);
    require(expected==got);if(got)require(same(a,b));++checked;
}
static std::vector<unsigned char> packed(unsigned field,unsigned width){
    std::vector<unsigned char> bytes(5);bytes[0]=7;uint32_t widths=width<<(field*4);
    for(unsigned i=0;i<4;++i)bytes[1+i]=uint8_t(widths>>(i*8));
    for(unsigned i=0;i<width;++i)bytes.push_back(uint8_t(0x80+i*13));return bytes;
}
int main(){try{
    std::vector<std::vector<unsigned char>> guards;
    for(unsigned field=0;field<7;++field)for(unsigned width=0;width<=8;++width){
        auto bytes=packed(field,width);check(bytes.data(),bytes.size(),1);
        for(size_t n=0;n<bytes.size();++n)check(bytes.data(),n,1);
        bytes.push_back(0);check(bytes.data(),bytes.size(),1);bytes.pop_back();guards.push_back(bytes);
    }
    for(unsigned field=0;field<7;++field)for(unsigned width=9;width<=15;++width){auto bytes=packed(field,width);check(bytes.data(),bytes.size(),1);}
    {auto bytes=packed(0,0);bytes[4]|=0x80;check(bytes.data(),bytes.size(),1);}
    {unsigned char bytes[64]{};check(bytes,0,0);check(bytes,0,1025);check(bytes,62,1);}
    std::mt19937_64 random(0x7153c001);unsigned char encoded[traceq::chunks::CAPACITY];
    for(unsigned trial=0;trial<128;++trial){
        size_t count=trial<4?size_t(1)<<trial:trial%11==0?1024:1+random()%17;
        std::vector<Event> events;
        auto value=[&](){unsigned n=random()%9;return n==8?random():random()&((uint64_t(1)<<(n*8))-1);};
        for(size_t i=0;i<count;++i)events.push_back({random()&255,value(),value(),value(),value(),value(),value(),value()});
        size_t size=traceq::chunks::encode(events.data(),count,encoded,sizeof encoded);require(size);
        std::vector<Event> decoded;require(traceq::chunks::decode(encoded,size,count,decoded) && same(events,decoded));
        check(encoded,size,count);
        if(count<=3)for(size_t n=0;n<size;++n)check(encoded,n,count);
        // Exercise unaligned inputs and every short tail length in long blocks.
        std::vector<unsigned char> unaligned(1+size);memcpy(unaligned.data()+1,encoded,size);check(unaligned.data()+1,size,count);
        for(size_t tail=0;tail<std::min(size,size_t(64));++tail)check(encoded,size-tail-1,count);
        if(size<=256)guards.emplace_back(encoded,encoded+size);
    }
#if defined(__unix__) || defined(__APPLE__)
    size_t page=size_t(sysconf(_SC_PAGESIZE));auto* memory=static_cast<unsigned char*>(mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    require(memory!=MAP_FAILED);require(mprotect(memory+page,page,PROT_NONE)==0);
    // Each buffer, including its final packed field, ends exactly at PROT_NONE.
    for(const auto&bytes:guards){auto*start=memory+page-bytes.size();memcpy(start,bytes.data(),bytes.size());
        for(size_t count=1;count<=3;++count)check(start,bytes.size(),count);}
    require(munmap(memory,page*2)==0);
#endif
    printf("PASS %u packed width/truncation/unaligned/guard-page checks and128 seeded roundtrips\n",checked);return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
