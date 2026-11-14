#include "state_stream.h"
#include <memory>
#include <traceq/chunk_stream.h>

namespace traceq::stream {
using namespace traceq::writes;
bool is_state_stream(int argc,char** argv) {
    // Try existing operands as files: command argument order remains flexible.
    for(int i=1;i<argc;++i) {
        if(argv[i][0]=='-')continue;
        std::unique_ptr<FILE,decltype(&fclose)> file(fopen(argv[i],"rb"),fclose);
        unsigned char header[FRAME_SIZE];
        if(file && fread(header,1,sizeof header,file.get())==sizeof header &&
           (!memcmp(header,MAGIC,8) || !memcmp(header,traceq::chunks::MAGIC,8)) && get64(header+48)==2)return true;
    }
    return false;
}
bool read(const std::string& path,Info& info,
          const std::function<void(const Group&,const Info&)>& callback,std::string& error) {
    auto fail=[&](const char* why){error=why;return false;};
    std::unique_ptr<FILE,decltype(&fclose)> in(fopen(path.c_str(),"rb"),fclose);
    if(!in)return fail("cannot open capture");
    unsigned char b[FRAME_SIZE];
    traceq::chunks::Input input(in.get());
    if(!input.header(b))return fail("invalid stream header");
    info=Info{};info.header={get64(b+8),get64(b+16),get64(b+24),get64(b+32),get64(b+40),get64(b+48)};
    info.chunked=input.chunked();
    const auto& h=info.header;
    if(h.profile!=2 || get64(b+56)!=FRAME_SIZE || !h.code_size || h.code_size>UINT64_MAX-h.code_base ||
       !h.data_size || h.data_size>UINT64_MAX-h.data_base)return fail("invalid execution-state profile");
    Registers cache{};Group g;bool active=false,post_started=false,post_records=false,expect_post=false;
    bool open_exit=false,exit_has_gap=false;uint64_t exit_seq=0;
    auto flush=[&](){
        if(!active)return true;
        if(open_exit && exit_seq<g.seq)return fail("missing scope reentry record");
        if(g.exit.transfer) {
            if(g.exit.transfer!=RETURN && !g.gap)return fail("scope exit without coverage gap");
            for(const auto& value:g.pre)if(!value.known)return fail("incomplete scope exit state");
            exit_has_gap=g.gap;
        }
        if((post_records || !g.accesses.empty()) && !g.committed)return fail("unconfirmed post-instruction records");
        if(expect_post && !g.committed && !g.gap)return fail("missing required completion observation");
        callback(g,info);
        if(g.committed)cache=g.post;
        else if(g.gap)cache=Registers{};
        else cache=g.pre;
        return true;
    };
    auto post=[&](){if(!post_started){g.post=g.pre;post_started=true;}};
    for(;;) {
        Event e;
        if(!input.next(e))return fail("invalid or truncated stream: missing END or malformed block");
        if(e.kind==FEATURES) {
            if(active || info.boundary_capture || e.seq || e.pc || e.address!=FEATURE_BOUNDARIES || e.size || e.low>1 || e.high || e.detail)
                return fail("invalid stream features");
            info.boundary_capture=true;info.external_followed=e.low==1;continue;
        }
        if(e.kind==MODULE) {
            if(!info.boundary_capture || active || !e.address || e.address>UINT64_MAX-e.pc ||
               !e.size || e.size>24 || e.seq>4096-e.size)return fail("invalid module metadata");
            auto& module=info.modules[e.pc];
            if(e.seq!=module.name.size() || (e.seq && module.size!=e.address))return fail("inconsistent module metadata");
            module.base=e.pc;module.size=e.address;
            unsigned char part[24];put64(part,e.low);put64(part+8,e.high);put64(part+16,e.detail);
            module.name.append(reinterpret_cast<char*>(part),size_t(e.size));continue;
        }
        if(e.kind==SITE) {
            if(e.pc<h.code_base || e.pc-h.code_base>=h.code_size || !e.size || e.size>24 || e.seq+e.size>256)
                return fail("invalid site metadata");
            auto& text=info.sites[e.pc];
            if(e.address>UINT32_MAX)return fail("invalid instruction bytes");
            auto word=info.words.emplace(e.pc,uint32_t(e.address));
            if(word.first->second!=e.address)return fail("changed code inside fixed-code profile");
            if(e.seq!=text.size())return fail("noncontiguous site text");
            unsigned char part[24];put64(part,e.low);put64(part+8,e.high);put64(part+16,e.detail);
            text.append(reinterpret_cast<char*>(part),size_t(e.size));continue;
        }
        if(e.kind==EXEC) {
            if(!flush())return false;
            if(e.seq!=info.instructions || e.pc<h.code_base || e.pc-h.code_base>=h.code_size ||
               (e.pc-h.code_base)%4 || e.address>UINT32_MAX || e.detail>1 || e.size || e.low || e.high ||
               !info.sites.count(e.pc) || info.words.at(e.pc)!=e.address)return fail("invalid instruction event");
            g=Group{};g.seq=e.seq;g.pc=e.pc;g.word=e.address;g.pre=cache;
            active=true;post_started=post_records=false;expect_post=e.detail==1;
            ++info.instructions;continue;
        }
        if(e.kind==END) {
            if(!flush())return false;
            if(e.seq!=info.instructions || e.address!=info.writes || e.size!=info.gaps ||
               e.low!=info.reads || e.high!=info.commits || e.detail!=2 || e.pc)
                return fail("invalid completion counters");
            if(!input.finished())return fail("trailing bytes or read error");
            return true;
        }
        if(e.kind==GAP && e.detail==EXCLUSIVE_REGION && e.seq==info.instructions && e.pc==0) {
            info.unpositioned_gap=true;++info.gaps;++info.gap_reasons[e.detail];continue;
        }
        if(!active || e.seq!=g.seq || e.pc!=g.pc)return fail("event outside its instruction");
        if(e.kind==SCOPE_EXIT) {
            if(!info.boundary_capture || open_exit || g.exit.transfer || g.committed || g.gap || expect_post ||
               (e.address>=h.code_base && e.address-h.code_base<h.code_size) ||
               e.size<CALL || e.size>RETURN || e.low!=(e.size==CALL?e.pc+4:0) || e.high || e.detail!=1)
                return fail("invalid scope exit");
            g.exit={e.address,e.size,e.low};open_exit=true;exit_seq=g.seq;++info.exits;
        } else if(e.kind==SCOPE_REENTER) {
            if(!info.boundary_capture || !open_exit || !exit_has_gap || g.reentered || e.address!=exit_seq || g.seq!=exit_seq+1 ||
               g.gap || g.committed || post_records || e.size || e.low || e.high || e.detail!=1)
                return fail("invalid scope reentry");
            for(const auto& value:g.pre)if(!value.known)return fail("incomplete scope reentry state");
            g.reentered=true;g.exit_seq=exit_seq;open_exit=false;++info.reentries;
        } else if(e.kind==GAP) {
            if(e.detail<1 || e.detail>6)return fail("invalid gap reason");
            if(g.committed)return fail("gap after instruction commit");
            ++info.gaps;g.gap=true;post_started=true;g.post=Registers{};
            ++g.gap_count;
            g.gap_reason_mask|=uint64_t(1)<<e.detail;
            ++info.gap_reasons[e.detail];
            if(e.detail==UNSUPPORTED){const auto& text=info.sites.at(g.pc);++info.unsupported_mnemonics[text.substr(0,text.find(' '))];}
        } else if(e.kind==REG_PRE || e.kind==REG_POST) {
            if(e.address>=REGISTER_COUNT || e.size!=(e.address<33?8:16) || e.detail!=1 ||
               (e.size==8 && e.high) || g.committed)return fail("invalid register observation");
            Value value{static_cast<unsigned __int128>(e.low)|(static_cast<unsigned __int128>(e.high)<<64),true};
            if(e.kind==REG_PRE) {
                if(post_records || g.gap || !g.accesses.empty())return fail("late pre-state observation");
                g.pre[e.address]=value;
            } else {
                if(!expect_post)return fail("unexpected post-state observation");
                post();g.post[e.address]=value;post_records=true;
            }
        } else if(e.kind==READ || e.kind==WRITE) {
            if(!expect_post || g.committed || g.accesses.size()>=4 || !e.size || e.size>16 ||
               e.address<h.data_base || e.size>h.data_size || e.address-h.data_base>h.data_size-e.size ||
               e.detail>1 || (e.kind==WRITE && e.detail!=1))return fail("invalid memory event");
            g.accesses.push_back(e);
            if(e.kind==READ)++info.reads;else ++info.writes;
            if(e.kind==READ && e.detail==0)++info.unknown_reads;
        } else if(e.kind==COMMIT) {
            if(!expect_post || g.committed || e.address || e.size || e.low || e.high || e.detail!=1)
                return fail("invalid instruction commit");
            post();g.committed=true;++info.commits;
        } else return fail("unknown execution-state record");
    }
}
} // namespace traceq::stream
