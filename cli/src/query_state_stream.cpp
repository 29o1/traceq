#include "state_query.h"
#include "cli_args.h"
#include "emit.h"
#include "query_common.h"
#include <algorithm>

namespace traceq::stream {
namespace {
using namespace query_detail;
struct Byte {
    bool known=false;uint8_t value=0;uint64_t seq=0,pc=0,kind=0;
    bool observed=false;uint64_t gap_epoch=0;
};
struct Span { Group exit,entry;bool reentered=false; };

}
int command(const std::string& name,int argc,char** argv) {
    using namespace traceq::writes;
    std::string path,phase=name=="reg-state"?"pre":"post";
    uint64_t base=0,len=0,at=UINT64_MAX,from=0,to=UINT64_MAX,limit=20,offset=0;
    bool json=false,has_range=false,has_at=false,read_only=false,write_only=false;
    bool gaps_only=false;
    std::vector<Register> registers;std::vector<uint64_t> pcs,offs;
    for(int i=1;i<argc;++i)if(!strcmp(argv[i],"--json"))json=true;
    auto fail=[&](const std::string& message,int code=1){
        std::string error;emit::kv_str(error,"code",code==2?"ARGUMENT":"TRACE_ERROR");
        emit::kv_str(error+=",","message",message);
        if(json)printf("{\"error\":{%s}}\n",error.c_str());else fprintf(stderr,"%s: %s\n",name.c_str(),message.c_str());
        return code;
    };
    try {
        for(int i=1;i<argc;++i) {
            std::string arg=argv[i];auto next=[&](){if(i+1>=argc)throw std::invalid_argument("missing "+arg+" value");return std::string(argv[++i]);};
            if(arg=="--help" || arg=="-h") {
                printf("execution-state stream queries (profile 2):\n"
                    "  traceq stat FILE [--json]\n"
                    "  traceq instructions FILE [--from E --to E] [--gaps] [--limit N --offset N] [--json]\n"
                    "  traceq boundaries FILE [--from E --to E] [--reg x0]... [--limit N --offset N] [--json]\n"
                    "  traceq find-pc FILE (--off O | --addr A)... [--limit N] [--json]\n"
                    "  traceq reg-state FILE --at-ev E [--phase pre|post] [--reg x0]... [--json]\n"
                    "  traceq mem-access FILE --range BASE,LEN [--read|--write] [--from E --to E] [--json]\n"
                    "  traceq mem-state FILE --range BASE,LEN --at-ev E [--phase pre|post] [--json]\n"
                    "  traceq last-writers FILE --range BASE,LEN [--at-seq E] [--json]\n");return 0;
            }
            if(arg=="--json")continue;
            if(arg=="--gaps"){gaps_only=true;continue;}
            if(arg=="--range") {
                auto value=next();auto pos=value.find(',');
                if(has_range || pos==std::string::npos)throw std::invalid_argument("one --range BASE,LEN is required");
                base=parse_u64(value.substr(0,pos));len=parse_u64(value.substr(pos+1));has_range=true;
            } else if(arg=="--at-ev" || arg=="--at-seq"){at=parse_u64(next());has_at=true;}
            else if(arg=="--from")from=parse_u64(next());else if(arg=="--to")to=parse_u64(next());
            else if(arg=="--limit")limit=parse_u64(next());else if(arg=="--offset")offset=parse_u64(next());
            else if(arg=="--phase") {
                if(name=="boundaries")throw std::invalid_argument("boundaries exposes exit/reentry pre states; --phase does not apply");
                phase=next();
            }else if(arg=="--reg")registers.push_back(reg(next()));
            else if(arg=="--addr")pcs.push_back(parse_u64(next()));else if(arg=="--off")offs.push_back(parse_u64(next()));
            else if(arg=="--read")read_only=true;else if(arg=="--write")write_only=true;
            else if(!arg.empty() && arg[0]!='-' && path.empty())path=arg;
            else throw std::invalid_argument("unsupported argument: "+arg);
        }
        if(path.empty() || !limit || limit>4096 || from>to || (phase!="pre" && phase!="post") || (read_only && write_only))
            throw std::invalid_argument("invalid file, limits, window or phase");
        if(has_range && (!len || len>4096 || len>UINT64_MAX-base))throw std::invalid_argument("range length must be 1..4096 without overflow");
        if((name=="mem-access" || name=="mem-state" || name=="last-writers") && !has_range)throw std::invalid_argument("--range is required");
        if((name=="mem-state" || name=="reg-state") && !has_at)throw std::invalid_argument("--at-ev is required");
        if(name=="boundaries" && (has_range || has_at))throw std::invalid_argument("boundaries uses --from/--to exit events; --range and --at-ev/--at-seq do not apply");
        if(name=="find-pc" && pcs.empty() && offs.empty())throw std::invalid_argument("--addr or --off is required");
        if(registers.size()>65)throw std::invalid_argument("at most 65 registers per query");
        if(!registers.empty() && name!="reg-state" && name!="boundaries")throw std::invalid_argument("--reg applies to reg-state or boundaries");
        if((!pcs.empty() || !offs.empty()) && name!="find-pc")throw std::invalid_argument("PC selectors apply to find-pc");
        if((read_only || write_only) && name!="mem-access")throw std::invalid_argument("--read/--write apply to mem-access");
        if(gaps_only && name!="instructions")throw std::invalid_argument("--gaps applies to instructions");
    }catch(const std::invalid_argument& e){return fail(e.what(),2);}
    if(registers.empty()) {
        for(const char* r:{"x0","x1","x2","x3","x4","x5","x6","x7"})registers.push_back(reg(r));
        if(name=="boundaries")for(const char* r:{"x8","sp","lr"})registers.push_back(reg(r));
        else registers.push_back(reg("nzcv"));
    }
    std::vector<std::string> rows;uint64_t total=0;Info info;std::string error;
    std::vector<Byte> memory(len),selected;Group selected_group;bool selected_event=false,range_ok=true;
    std::vector<Span> spans;Span pending_span;bool span_open=false;
    uint64_t gap_epoch=0,last_gap_seq=0;
    auto keep=[&](std::string row){uint64_t n=total++;if(n>=offset && rows.size()<limit)rows.push_back(std::move(row));};
    auto keep_span=[&](){
        if(pending_span.exit.seq>=from && pending_span.exit.seq<=to) {
            uint64_t n=total++;if(n>=offset && spans.size()<limit)spans.push_back(std::move(pending_span));
        }
        span_open=false;
    };
    bool valid=read(path,info,[&](const Group& g,const Info& state){
        const auto& h=state.header;
        if(name=="boundaries") {
            if(g.reentered) {pending_span.entry=g;pending_span.reentered=true;keep_span();}
            if(g.exit.transfer) {pending_span=Span{};pending_span.exit=g;span_open=true;}
        }
        if(has_range && (base<h.data_base || len>h.data_size || base-h.data_base>h.data_size-len)){range_ok=false;return;}
        if(name=="reg-state" && g.seq==at){selected_group=g;selected_event=true;}
        if(name=="mem-state" && g.seq==at && phase=="pre"){selected=memory;selected_event=true;}
        if(g.gap && g.seq<=at) {
            gap_epoch+=g.gap_count;last_gap_seq=g.seq;
            for(auto& b:memory)b.known=false;
        }
        for(const auto& a:g.accesses) {
            if(has_range && (name=="mem-state" || name=="last-writers") && g.seq<=at &&
               (name=="mem-state" || a.kind==WRITE)) {
                uint64_t first=std::max(base,a.address),end=std::min(base+len,a.address+a.size);
                for(uint64_t p=first;p<end;++p){unsigned k=unsigned(p-a.address);
                    memory[p-base]={a.detail==1,uint8_t(k<8?a.low>>(k*8):a.high>>((k-8)*8)),g.seq,g.pc,a.kind,a.detail==1,gap_epoch};}
            }
            if(name!="mem-access" || g.seq<from || g.seq>to || (read_only && a.kind!=READ) || (write_only && a.kind!=WRITE) ||
               a.address>=base+len || a.address+a.size<=base)continue;
            std::string row;emit::kv_u64(row,"ev",g.seq);emit::kv_hex(row+=",","pc",g.pc);
            emit::kv_hex(row+=",","off",g.pc-h.code_base);emit::kv_str(row+=",","rw",a.kind==READ?"r":"w");
            emit::kv_hex(row+=",","addr",a.address);emit::kv_u64(row+=",","size",a.size);
            emit::kv_bool(row+=",","known",a.detail==1);
            if(a.detail==1)emit::kv_hex128(row+=",","val",static_cast<unsigned __int128>(a.low)|(static_cast<unsigned __int128>(a.high)<<64));
            else row+=",\"val\":null";
            emit::kv_str(row+=",","value_source",a.kind==READ?"load destination bits after completion":"store source bits; post callback confirmed");
            keep("{"+row+"}");
        }
        if(name=="mem-state" && g.seq==at && phase=="post") {
            selected=memory;if(!g.committed)for(auto& b:selected)b.known=false;
            selected_event=true;
        }
        if(name!="instructions" && name!="find-pc")return;
        if(g.seq<from || g.seq>to)return;
        if(gaps_only && !g.gap)return;
        if(name=="find-pc" && std::find(pcs.begin(),pcs.end(),g.pc)==pcs.end() &&
           std::find(offs.begin(),offs.end(),g.pc-h.code_base)==offs.end())return;
        std::string row;emit::kv_u64(row,"ev",g.seq);emit::kv_hex(row+=",","pc",g.pc);
        emit::kv_hex(row+=",","off",g.pc-h.code_base);emit::kv_hex(row+=",","opcode",g.word);
        emit::kv_str(row+=",","text",state.sites.at(g.pc));
        emit::kv_str(row+=",","completion",g.committed?"confirmed":"unobserved");
        emit::kv_bool(row+=",","post_observed",g.committed);
        emit::kv_bool(row+=",","gap",g.gap);keep("{"+row+"}");
    },error);
    if(!valid)return fail(error);
    if(!range_ok)return fail("query extends outside declared data range",2);
    if(has_at && at>=info.instructions)return fail("requested instruction is outside the capture",2);
    if(name=="boundaries") {
        if(span_open)keep_span();
        for(const auto& span:spans) {
            const auto& g=span.exit;std::string row;
            emit::kv_u64(row,"exit_ev",g.seq);row+=",\"source\":"+location(g.pc,info);
            emit::kv_hex(row+=",","source_off",g.pc-info.header.code_base);
            emit::kv_str(row+=",","instruction",info.sites.at(g.pc));
            row+=",\"target\":"+location(g.exit.target,info);
            emit::kv_str(row+=",","transfer",g.exit.transfer==CALL?"call":g.exit.transfer==RETURN?"return":"branch");
            emit::kv_str(row+=",","status",span.reentered?"reentered":"no_reentry_observed");
            if(g.exit.expected_return)emit::kv_hex(row+=",","expected_return_address",g.exit.expected_return);
            else row+=",\"expected_return_address\":null";
            row+=",\"exit_registers\":"+register_values(g.pre,registers,info.unpositioned_gap);
            if(span.reentered) {
                emit::kv_u64(row+=",","reentry_ev",span.entry.seq);
                row+=",\"reentry\":"+location(span.entry.pc,info);
                row+=",\"reentry_registers\":"+register_values(span.entry.pre,registers,info.unpositioned_gap);
                if(g.exit.expected_return)emit::kv_bool(row+=",","reentry_matches_expected_return",span.entry.pc==g.exit.expected_return);
                else row+=",\"reentry_matches_expected_return\":null";
            } else row+=",\"reentry_ev\":null,\"reentry\":null,\"reentry_registers\":null,\"reentry_matches_expected_return\":null";
            emit::kv_str(row+=",","memory_effects","unobserved");
            rows.push_back("{"+row+"}");
        }
    } else if(name=="stat") {
        std::string row;emit::kv_str(row,"format",info.chunked?"GTSC001":"GTSW001");emit::kv_u64(row+=",","profile",2);
        emit::kv_u64(row+=",","sites",info.sites.size());emit::kv_u64(row+=",","register_slots",REGISTER_COUNT);
        keep("{"+row+"}");
        // These summaries describe actual gap records, separately from paging.
    } else if(name=="reg-state") {
        if(!selected_event)return fail("requested state was not observed",2);
        const auto& values=phase=="pre"?selected_group.pre:selected_group.post;
        for(const auto& r:registers) {
            bool known=r.slot<0 || (!info.unpositioned_gap && (phase=="pre" || selected_group.committed) && values[r.slot].known);
            std::string row;emit::kv_str(row,"reg",r.name);emit::kv_bool(row+=",","known",known);
            if(known)emit::kv_hex128(row+=",","val",r.slot<0?0:masked(values[r.slot].bits,r.bits));else row+=",\"val\":null";
            keep("{"+row+"}");
        }
    } else if(name=="mem-state" || name=="last-writers") {
        if(name=="last-writers")selected=memory;
        if(info.unpositioned_gap)for(auto& b:selected)b.known=false;
        for(size_t i=0;i<selected.size();++i){const auto& b=selected[i];std::string row;
            emit::kv_hex(row,"address",base+i);emit::kv_bool(row+=",","known",b.known);
            if(b.known){emit::kv_hex(row+=",","value",b.value);emit::kv_u64(row+=",",name=="last-writers"?"writer_seq":"observed_ev",b.seq);
                emit::kv_hex(row+=",","pc",b.pc);emit::kv_hex(row+=",","pc_offset",b.pc-info.header.code_base);}
            else row+=",\"value\":null,\"writer_seq\":null,\"pc\":null";
            if(name=="last-writers") {
                if(b.observed) {
                    std::string evidence;emit::kv_hex(evidence,"value",b.value);
                    emit::kv_u64(evidence+=",","writer_seq",b.seq);emit::kv_hex(evidence+=",","pc",b.pc);
                    emit::kv_hex(evidence+=",","pc_offset",b.pc-info.header.code_base);
                    emit::kv_u64(evidence+=",","gaps_since",gap_epoch-b.gap_epoch);
                    if(gap_epoch>b.gap_epoch)emit::kv_u64(evidence+=",","latest_gap_ev",last_gap_seq);
                    else evidence+=",\"latest_gap_ev\":null";
                    row+=",\"last_observed_write\":{"+evidence+"}";
                } else row+=",\"last_observed_write\":null";
            }
            keep("{"+row+"}");
        }
    }
    std::string meta;emit::kv_u64(meta,"total",total);emit::kv_u64(meta+=",","shown",rows.size());
    bool truncated=offset<total && rows.size()<total-offset;emit::kv_bool(meta+=",","truncated",truncated);
    std::string next;
    if(truncated) {
        next="traceq "+name;
        for(int i=1;i<argc;++i){if(!strcmp(argv[i],"--offset")){++i;continue;}next+=" "+shell_arg(argv[i]);}
        next+=" --offset "+std::to_string(offset+rows.size());
    }
    emit::kv_str(meta+=",","next",next);emit::kv_u64(meta+=",","capture_gaps",info.gaps);
    emit::kv_u64(meta+=",","instructions",info.instructions);emit::kv_u64(meta+=",","reads",info.reads);
    emit::kv_u64(meta+=",","unknown_reads",info.unknown_reads);
    emit::kv_u64(meta+=",","stores",info.writes);emit::kv_u64(meta+=",","confirmed_instructions",info.commits);
    emit::kv_bool(meta+=",","unpositioned_gap",info.unpositioned_gap);
    emit::kv_bool(meta+=",","boundary_capture",info.boundary_capture);
    emit::kv_str(meta+=",","external_execution",info.external_followed?"followed_without_instruction_records":"excluded_or_unspecified");
    emit::kv_u64(meta+=",","scope_exits",info.exits);emit::kv_u64(meta+=",","scope_reentries",info.reentries);
    if(name=="boundaries")emit::kv_str(meta+=",","pairing","each exit to next observed in-scope instruction; not call/return matching");
    if(name=="stat") {
        meta+=",\"gap_reasons\":{";
        const char* labels[]={"unused","unsupported","unconfirmed_store","foreign_thread","exclusive_region","outside_data_range","outside_code_range"};
        for(unsigned i=1;i<7;++i){if(i>1)meta+=",";emit::kv_u64(meta,labels[i],info.gap_reasons[i]);}
        meta+="},\"unsupported_mnemonics\":{";
        std::vector<std::pair<std::string,uint64_t>> counts(info.unsupported_mnemonics.begin(),info.unsupported_mnemonics.end());
        std::sort(counts.begin(),counts.end());
        for(size_t i=0;i<counts.size();++i){if(i)meta+=",";emit::kv_u64(meta,counts[i].first.c_str(),counts[i].second);}
        meta+="}";
    }
    emit::kv_hex(meta+=",","thread_id",info.header.thread_id);
    emit::kv_hex(meta+=",","code_base",info.header.code_base);emit::kv_u64(meta+=",","code_size",info.header.code_size);
    emit::kv_hex(meta+=",","data_base",info.header.data_base);
    if(info.header.data_size>9007199254740991ULL)emit::kv_hex(meta+=",","data_size",info.header.data_size);
    else emit::kv_u64(meta+=",","data_size",info.header.data_size);
    if(name=="reg-state" || name=="mem-state")emit::kv_str(meta+=",","phase",phase);
    emit::kv_str(meta+=",","scope","observations within declared single-thread code/data ranges");
    if(json){printf("{\"data\":[");for(size_t i=0;i<rows.size();++i)printf("%s%s",i?",":"",rows[i].c_str());printf("],\"meta\":{%s}}\n",meta.c_str());}
    else {for(const auto& row:rows)puts(row.c_str());printf("meta: {%s}\n",meta.c_str());}
    return 0;
}
} // namespace traceq::stream
