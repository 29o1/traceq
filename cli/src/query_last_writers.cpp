#include <traceq/write_stream.h>
#include "cli_args.h"
#include "emit.h"
#include "query_common.h"
#include <algorithm>
#include <array>
#include <memory>

// Experimental streaming query. Memory is bounded by the requested byte
// range, not by the trace length. All frames are validated before output.
int cmd_last_writers(int argc, char** argv) {
    using namespace traceq::writes;
    std::string path;
    uint64_t base=0, length=0, at=UINT64_MAX, limit=20, offset=0;
    bool json=false, have_range=false;
    for (int i=1; i<argc; ++i) if (!strcmp(argv[i],"--json")) json=true;
    auto fail = [&](const char* code,const std::string& message,int rc=1) {
        if (json) {
            std::string body; traceq::emit::kv_str(body,"code",code);
            traceq::emit::kv_str(body += ",","message",message);
            printf("{\"error\":{%s}}\n",body.c_str());
        } else fprintf(stderr,"last-writers: %s: %s\n",code,message.c_str());
        return rc;
    };
    try {
        for (int i=1; i<argc; ++i) {
            std::string arg=argv[i];
            auto next=[&]() -> const char* {
                if (i+1>=argc) throw std::invalid_argument("missing value for "+arg);
                return argv[++i];
            };
            if (arg=="--help" || arg=="-h") {
                printf("usage: traceq last-writers trace.gtsw --range BASE,LEN "
                       "[--at-seq N] [--limit N] [--offset N] [--json]\n"
                       "  last observed completed store per byte, inside the declared scope\n"
                       "  experimental GTSW v1; LEN and limit must be 1..4096\n"); return 0;
            } else if (arg=="--range") {
                std::string value=next(); auto comma=value.find(',');
                if (comma==std::string::npos || have_range) throw std::invalid_argument("one --range BASE,LEN required");
                base=parse_u64(value.substr(0,comma)); length=parse_u64(value.substr(comma+1)); have_range=true;
            } else if (arg=="--at-seq") at=parse_u64(next());
            else if (arg=="--limit") limit=parse_u64(next());
            else if (arg=="--offset") offset=parse_u64(next());
            else if (arg=="--json") {}
            else if (!arg.empty() && arg[0]!='-' && path.empty()) path=arg;
            else throw std::invalid_argument("unexpected argument: "+arg);
        }
    } catch (const std::invalid_argument& e) { return fail("ARGUMENT",e.what(),2); }
    if (path.empty() || !have_range || !length || length>4096 || !limit || limit>4096 ||
        length>UINT64_MAX-base || offset>length) return fail("ARGUMENT","invalid path, range, limit or offset",2);
    std::unique_ptr<FILE,decltype(&fclose)> in(fopen(path.c_str(),"rb"),fclose);
    if (!in) return fail("OPEN","cannot open "+path);
    std::array<unsigned char,FRAME_SIZE> frame{};
    if (fread(frame.data(),1,FRAME_SIZE,in.get())!=FRAME_SIZE || memcmp(frame.data(),MAGIC,8))
        return fail("FORMAT","expected a GTSW v1 header");
    Header h{get64(frame.data()+8),get64(frame.data()+16),get64(frame.data()+24),
             get64(frame.data()+32),get64(frame.data()+40),get64(frame.data()+48)};
    if (!h.code_size || h.code_size>UINT64_MAX-h.code_base || !h.data_size ||
        h.data_size>UINT64_MAX-h.data_base || h.profile!=1 || get64(frame.data()+56)!=FRAME_SIZE)
        return fail("FORMAT","unsupported or invalid capture profile");
    if (base<h.data_base || length>h.data_size || base-h.data_base>h.data_size-length)
        return fail("RANGE","query extends outside declared data range",2);
    struct Byte { bool known=false; uint8_t value=0; uint64_t seq=0,pc=0; };
    std::vector<Byte> bytes(length);
    uint64_t instructions=0,writes=0,gaps=0,selected_gaps=0,current_pc=0;
    bool ended=false;
    for (;;) {
        size_t n=fread(frame.data(),1,FRAME_SIZE,in.get());
        if (n!=FRAME_SIZE) return fail("TRUNCATED","missing or incomplete END frame");
        Event e=decode_event(frame.data());
        if (e.kind==EXEC) {
            if (e.seq!=instructions || e.pc<h.code_base || e.pc-h.code_base>=h.code_size ||
                (e.pc-h.code_base)%4 || e.address || e.size || e.low || e.high || e.detail)
                return fail("FORMAT","invalid instruction sequence");
            ++instructions; current_pc=e.pc;
        } else if (e.kind==WRITE) {
            if (!instructions || e.seq!=instructions-1 || e.pc!=current_pc ||
                !e.size || e.size>16 || e.detail!=1 || e.address<h.data_base ||
                e.size>h.data_size || e.address-h.data_base>h.data_size-e.size)
                return fail("FORMAT","invalid store frame");
            ++writes;
            if (e.seq>at) continue;
            uint64_t lo=std::max(base,e.address), hi=std::min(base+length,e.address+e.size);
            for (uint64_t addr=lo; addr<hi; ++addr) {
                unsigned k=unsigned(addr-e.address);
                bytes[addr-base]={true,uint8_t(k<8 ? e.low>>(8*k) : e.high>>(8*(k-8))),e.seq,e.pc};
            }
        } else if (e.kind==GAP) {
            if (e.seq>instructions || (e.seq<instructions && e.seq!=instructions-1) ||
                e.detail<UNSUPPORTED || e.detail>OUTSIDE_DATA_RANGE)
                return fail("FORMAT","invalid gap frame");
            ++gaps;
            // Exclusive-region translation has no precise dynamic position;
            // its final conservative gap invalidates historical queries too.
            if (e.seq<=at || e.detail==EXCLUSIVE_REGION) {
                ++selected_gaps; for (auto& b:bytes) b.known=false;
            }
        } else if (e.kind==END) {
            if (e.seq!=instructions || e.address!=writes || e.size!=gaps ||
                e.detail!=1 || e.pc || e.low || e.high) return fail("FORMAT","invalid END counters");
            if (fgetc(in.get())!=EOF || ferror(in.get())) return fail("FORMAT","trailing bytes or read error");
            ended=true; break;
        } else return fail("FORMAT","unknown frame kind");
    }
    if (!ended || (at!=UINT64_MAX && at>=instructions)) return fail("RANGE","at-seq is outside captured instructions",2);
    uint64_t shown=std::min(limit,length-offset);
    if (json) printf("{\"data\":[");
    for (uint64_t i=offset; i<offset+shown; ++i) {
        const Byte& b=bytes[i];
        if (json) {
            if (i!=offset) printf(",");
            std::string row;
            traceq::emit::kv_hex(row,"address",base+i);
            traceq::emit::kv_bool(row+=",","known",b.known);
            if (b.known) {
                traceq::emit::kv_hex(row+=",","value",b.value);
                traceq::emit::kv_u64(row+=",","writer_seq",b.seq);
                traceq::emit::kv_hex(row+=",","pc",b.pc);
                traceq::emit::kv_hex(row+=",","pc_offset",b.pc-h.code_base);
            } else row+=",\"value\":null,\"writer_seq\":null,\"pc\":null";
            printf("{%s}",row.c_str());
        } else {
            printf("0x%llx ",static_cast<unsigned long long>(base+i));
            if (b.known) printf("0x%02x writer=%llu pc=0x%llx\n",b.value,
                static_cast<unsigned long long>(b.seq),static_cast<unsigned long long>(b.pc));
            else printf("unknown\n");
        }
    }
    const bool truncated=offset+shown<length;
    std::string next;
    if (truncated) {
        next="traceq last-writers "+shell_arg(path)+" --range "+traceq::emit::hex64(base)+","+std::to_string(length)+
            " --limit "+std::to_string(limit)+" --offset "+std::to_string(offset+shown);
        if (at!=UINT64_MAX) next+=" --at-seq "+std::to_string(at);
        if (json) next+=" --json";
    }
    if (json) {
        std::string meta;
        traceq::emit::kv_u64(meta,"total",length);traceq::emit::kv_u64(meta+=",","shown",shown);
        traceq::emit::kv_bool(meta+=",","truncated",truncated);traceq::emit::kv_str(meta+=",","next",next);
        traceq::emit::kv_u64(meta+=",","instructions",instructions);traceq::emit::kv_u64(meta+=",","stores",writes);
        traceq::emit::kv_u64(meta+=",","capture_gaps",gaps);traceq::emit::kv_u64(meta+=",","selected_gaps",selected_gaps);
        traceq::emit::kv_hex(meta+=",","thread_id",h.thread_id);
        traceq::emit::kv_str(meta+=",","scope","last observed stores in declared single-thread code/data ranges");
        traceq::emit::kv_str(meta+=",","value_source","pre-instruction source bits; store completion confirmed by post callback");
        printf("],\"meta\":{%s}}\n",meta.c_str());
    } else printf("shown=%llu total=%llu gaps=%llu%s\n",static_cast<unsigned long long>(shown),
        static_cast<unsigned long long>(length),static_cast<unsigned long long>(gaps),truncated?" (truncated)":"");
    return 0;
}
