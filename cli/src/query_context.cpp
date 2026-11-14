#include "state_query.h"
#include "query_common.h"
#include <algorithm>
#include <cctype>

namespace traceq::stream {
namespace {
using namespace query_detail;
Register canonical(int slot) {
    return reg(slot<31?"x"+std::to_string(slot):slot==31?"sp":slot==32?"nzcv":"v"+std::to_string(slot-33));
}
std::vector<Register> automatic_registers(const Group& g,const std::string& text) {
    // Select explicit operand names lexically, not inferred read/write sets.
    // Full-width slots also retain W/X aliases and SIMD upper-bit changes.
    bool slots[writes::REGISTER_COUNT]{};slots[30]=slots[31]=slots[32]=true;
    bool zero=false;
    for(size_t i=0;i<text.size();) {
        if(!std::isalnum(static_cast<unsigned char>(text[i])) && text[i]!='_'){++i;continue;}
        size_t start=i++;
        while(i<text.size() && (std::isalnum(static_cast<unsigned char>(text[i])) || text[i]=='_'))++i;
        std::string token=text.substr(start,i-start);
        bool named=token=="sp" || token=="wsp" || token=="lr" || token=="fp" || token=="nzcv" || token=="xzr" || token=="wzr";
        bool numbered=token.size()>1 && std::string("xwvqdsbh").find(token[0])!=std::string::npos &&
            std::all_of(token.begin()+1,token.end(),[](unsigned char c){return std::isdigit(c);});
        if(!named && !numbered)continue;
        try {auto r=reg(token);if(r.slot<0)zero=true;else slots[r.slot]=true;}catch(const std::invalid_argument&){}
    }
    if(g.committed)for(unsigned i=0;i<writes::REGISTER_COUNT;++i)
        if(g.pre[i].known && g.post[i].known && g.pre[i].bits!=g.post[i].bits)slots[i]=true;
    std::vector<Register> selected;
    for(unsigned i=0;i<writes::REGISTER_COUNT;++i)if(slots[i])selected.push_back(canonical(i));
    if(zero)selected.push_back(reg("xzr"));
    return selected;
}
std::string memory_json(const Group& g) {
    std::string rows="[";
    for(size_t i=0;i<g.accesses.size();++i) {
        const auto& a=g.accesses[i];std::string row;
        emit::kv_str(row,"rw",a.kind==writes::READ?"r":"w");emit::kv_hex(row+=",","addr",a.address);
        emit::kv_u64(row+=",","size",a.size);emit::kv_bool(row+=",","known",a.detail==1);
        if(a.detail)emit::kv_hex128(row+=",","val",static_cast<unsigned __int128>(a.low)|(static_cast<unsigned __int128>(a.high)<<64));
        else row+=",\"val\":null";
        emit::kv_str(row+=",","value_source",a.kind==writes::READ?"load destination bits after completion":"store source bits; post callback confirmed");
        if(i)rows+=",";rows+="{"+row+"}";
    }
    return rows+"]";
}
}

int context_command(int argc,char** argv) {
    std::string path;bool json=false;
    uint64_t before=2,after=2,limit=20,offset=0;
    std::vector<uint64_t> anchors;std::vector<Register> registers;
    for(int i=1;i<argc;++i)if(!strcmp(argv[i],"--json"))json=true;
    auto fail=[&](const std::string& message,int code) {
        std::string row;emit::kv_str(row,"code",code==2?"ARGUMENT":"TRACE_ERROR");emit::kv_str(row+=",","message",message);
        if(json)printf("{\"error\":{%s}}\n",row.c_str());else fprintf(stderr,"context: %s\n",message.c_str());return code;
    };
    try {
        for(int i=1;i<argc;++i) {
            std::string arg=argv[i];auto next=[&](){if(i+1>=argc)throw std::invalid_argument("missing "+arg+" value");return std::string(argv[++i]);};
            if(arg=="--help" || arg=="-h") {
                puts("traceq context FILE --at-ev E [--at-ev E ...] [--before N --after N] [--reg R ...] [--limit N --offset N] [--json]\n"
                     "  One validated scan; overlapping windows merge in execution order.\n"
                     "  Default registers: full-width operand/changed slots plus x30, sp, nzcv.\n"
                     "  --reg selects explicit views. Unknown post-state stays null.");return 0;
            }
            if(arg=="--json")continue;
            if(arg=="--at-ev")anchors.push_back(parse_u64(next()));
            else if(arg=="--before")before=parse_u64(next());else if(arg=="--after")after=parse_u64(next());
            else if(arg=="--limit")limit=parse_u64(next());else if(arg=="--offset")offset=parse_u64(next());
            else if(arg=="--reg")registers.push_back(reg(next()));
            else if(!arg.empty() && arg[0]!='-' && path.empty())path=arg;
            else throw std::invalid_argument("unsupported argument: "+arg);
        }
        if(path.empty() || anchors.empty() || anchors.size()>64 || before>4096 || after>4096 || !limit || limit>4096 || registers.size()>65)
            throw std::invalid_argument("require FILE, 1..64 events, before/after 0..4096, limit 1..4096, at most 65 registers");
    }catch(const std::invalid_argument& e){return fail(e.what(),2);}
    std::sort(anchors.begin(),anchors.end());anchors.erase(std::unique(anchors.begin(),anchors.end()),anchors.end());
    std::vector<std::pair<uint64_t,uint64_t>> windows;
    for(uint64_t at:anchors) {
        uint64_t start=at>=before?at-before:0,end=after>UINT64_MAX-at?UINT64_MAX:at+after;
        if(!windows.empty() && (windows.back().second==UINT64_MAX || start<=windows.back().second+1))windows.back().second=end;
        else windows.push_back({start,end});
    }
    std::vector<Group> selected;Info info;std::string error;uint64_t total=0;size_t window=0;
    bool valid=read(path,info,[&](const Group& g,const Info&) {
        while(window<windows.size() && g.seq>windows[window].second)++window;
        if(window==windows.size() || g.seq<windows[window].first)return;
        uint64_t n=total++;if(n>=offset && selected.size()<limit)selected.push_back(g);
    },error);
    if(!valid)return fail(error,1);
    if(anchors.back()>=info.instructions)return fail("requested event is outside the capture",2);
    std::vector<std::string> rows;
    for(const auto& g:selected) {
        const auto& text=info.sites.at(g.pc);auto chosen=registers.empty()?automatic_registers(g,text):registers;
        std::string row;emit::kv_u64(row,"ev",g.seq);emit::kv_hex(row+=",","pc",g.pc);
        emit::kv_hex(row+=",","off",g.pc-info.header.code_base);emit::kv_hex(row+=",","opcode",g.word);emit::kv_str(row+=",","text",text);
        emit::kv_bool(row+=",","focus",std::binary_search(anchors.begin(),anchors.end(),g.seq));
        emit::kv_str(row+=",","completion",g.committed?"confirmed":"unobserved");emit::kv_bool(row+=",","gap",g.gap);
        std::vector<std::string> reasons;const char* labels[]={"unused","unsupported","unconfirmed_store","foreign_thread","exclusive_region","outside_data_range","outside_code_range"};
        for(unsigned i=1;i<7;++i)if(g.gap_reason_mask&(uint64_t(1)<<i))reasons.push_back(labels[i]);
        row+=",\"gap_reasons\":"+emit::str_array(reasons);
        row+=",\"pre\":"+register_values(g.pre,chosen,info.unpositioned_gap);
        if(g.committed)row+=",\"post\":"+register_values(g.post,chosen,info.unpositioned_gap);
        else row+=",\"post\":null";
        row+=",\"memory\":"+memory_json(g);
        if(g.exit.transfer) {
            std::string edge;emit::kv_str(edge,"transfer",g.exit.transfer==writes::CALL?"call":g.exit.transfer==writes::RETURN?"return":"branch");
            edge+=",\"target\":"+location(g.exit.target,info);row+=",\"scope_exit\":{"+edge+"}";
        } else row+=",\"scope_exit\":null";
        if(g.reentered) {std::string edge;emit::kv_u64(edge,"exit_ev",g.exit_seq);row+=",\"scope_reentry\":{"+edge+"}";}
        else row+=",\"scope_reentry\":null";
        rows.push_back("{"+row+"}");
    }
    bool truncated=offset<total && rows.size()<total-offset;std::string next;
    if(truncated) {
        next="traceq context";for(int i=1;i<argc;++i){if(!strcmp(argv[i],"--offset")){++i;continue;}next+=" "+shell_arg(argv[i]);}
        next+=" --offset "+std::to_string(offset+rows.size());
    }
    std::string meta;emit::kv_u64(meta,"total",total);emit::kv_u64(meta+=",","shown",rows.size());
    emit::kv_bool(meta+=",","truncated",truncated);emit::kv_str(meta+=",","next",next);
    meta+=",\"requested_events\":[";for(size_t i=0;i<anchors.size();++i){if(i)meta+=",";meta+=std::to_string(anchors[i]);}meta+="]";
    emit::kv_u64(meta+=",","before",before);emit::kv_u64(meta+=",","after",after);
    emit::kv_u64(meta+=",","instructions",info.instructions);emit::kv_u64(meta+=",","capture_gaps",info.gaps);
    emit::kv_bool(meta+=",","unpositioned_gap",info.unpositioned_gap);emit::kv_bool(meta+=",","boundary_capture",info.boundary_capture);
    emit::kv_str(meta+=",","external_execution",info.external_followed?"followed_without_instruction_records":"excluded_or_unspecified");
    emit::kv_hex(meta+=",","code_base",info.header.code_base);emit::kv_hex(meta+=",","thread_id",info.header.thread_id);
    emit::kv_str(meta+=",","register_selection",registers.empty()?"operand_and_changed_full_slots_plus_x30_sp_nzcv":"explicit");
    emit::kv_str(meta+=",","validation","full stream through END");
    if(json) {printf("{\"data\":[");for(size_t i=0;i<rows.size();++i)printf("%s%s",i?",":"",rows[i].c_str());printf("],\"meta\":{%s}}\n",meta.c_str());}
    else {for(const auto& row:rows)puts(row.c_str());printf("meta: {%s}\n",meta.c_str());}
    return 0;
}
} // namespace traceq::stream
