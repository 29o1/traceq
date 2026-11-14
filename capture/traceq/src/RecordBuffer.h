#pragma once
#include <traceq/chunk_stream.h>
#include <array>
#ifdef TRACEQ_CAPTURE_PERF
#include <ctime>
#endif

enum class TraceqStorage { Legacy, Buffered, ChunkCpp, ChunkRust };
struct TraceqStorageOptions {
    TraceqStorage storage=TraceqStorage::Legacy;bool discard=false;
#ifdef TRACEQ_CAPTURE_PERF
    bool time_flush=false;
#endif
};
using TraceqEncoder=size_t(*)(const traceq::writes::Event*,size_t,unsigned char*,size_t);
#ifdef TRACEQ_RUST_CODEC
extern "C" size_t traceq_rust_encode(const traceq::writes::Event*,size_t,unsigned char*,size_t);
#endif

// Allocated once at begin on the traced thread. No allocation or queue mutex
// in append. Full blocks are submitted synchronously; no silent record loss.
class TraceqRecordBuffer {
    std::array<traceq::writes::Event,traceq::chunks::RECORDS> records_{};
    std::array<unsigned char,traceq::chunks::CAPACITY> bytes_{};
    FILE* out_=nullptr;size_t used_=0;TraceqStorageOptions options_{};
public:
    uint64_t blocks=0,events=0,encoded_bytes=0;
#ifdef TRACEQ_CAPTURE_PERF
    uint64_t encode_ns=0,write_ns=0;
    static uint64_t clock_ns(){timespec t{};clock_gettime(CLOCK_MONOTONIC,&t);return uint64_t(t.tv_sec)*1000000000+t.tv_nsec;}
#endif
    void begin(FILE* out,TraceqStorageOptions options){
        out_=out;options_=options;used_=0;blocks=events=encoded_bytes=0;
#ifdef TRACEQ_CAPTURE_PERF
        encode_ns=write_ns=0;
#endif
    }
    bool append(const traceq::writes::Event& event){records_[used_++]=event;++events;return used_!=records_.size() || flush();}
    bool flush() {
        if(!used_)return true;
#ifdef TRACEQ_CAPTURE_PERF
        uint64_t start=options_.time_flush?clock_ns():0;
#endif
        size_t size=0;bool compact=options_.storage==TraceqStorage::ChunkCpp || options_.storage==TraceqStorage::ChunkRust;
        if(compact) {
            TraceqEncoder encoder=traceq::chunks::encode;
#ifdef TRACEQ_RUST_CODEC
            if(options_.storage==TraceqStorage::ChunkRust)encoder=traceq_rust_encode;
#endif
            size=encoder(records_.data(),used_,bytes_.data(),bytes_.size());if(!size)return false;
        } else {
            for(size_t i=0;i<used_;++i){const auto& e=records_[i];
                const uint64_t values[]={e.kind,e.seq,e.pc,e.address,e.size,e.low,e.high,e.detail};
                for(unsigned j=0;j<8;++j)traceq::writes::put64(bytes_.data()+size+8*j,values[j]);size+=64;}
        }
        ++blocks;encoded_bytes+=size+(compact?16:0);
#ifdef TRACEQ_CAPTURE_PERF
        uint64_t encoded=options_.time_flush?clock_ns():0;
        if(options_.time_flush)encode_ns+=encoded-start;
#endif
        if(!options_.discard) {
            if(compact){unsigned char h[16];memcpy(h,traceq::chunks::BLOCK_MAGIC,8);
                traceq::chunks::put32(h+8,uint32_t(used_));traceq::chunks::put32(h+12,uint32_t(size));
                if(fwrite(h,1,sizeof h,out_)!=sizeof h)return false;}
            if(fwrite(bytes_.data(),1,size,out_)!=size)return false;
        }
#ifdef TRACEQ_CAPTURE_PERF
        if(options_.time_flush)write_ns+=clock_ns()-encoded;
#endif
        used_=0;return true;
    }
};
