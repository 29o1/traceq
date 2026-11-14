#pragma once
#include "state_stream.h"
#include "cli_args.h"
#include "emit.h"

namespace traceq::stream::query_detail {
struct Register { std::string name; int slot; unsigned bits; };
inline Register reg(const std::string& name) {
    if(name=="sp")return{name,31,64};if(name=="wsp")return{name,31,32};
    if(name=="fp")return{name,29,64};if(name=="lr")return{name,30,64};
    if(name=="nzcv")return{name,32,64};
    if(name=="xzr" || name=="wzr")return{name,-1,name=="xzr"?64u:32u};
    if(name.size()<2)throw std::invalid_argument("invalid register: "+name);
    unsigned n=parse_int(name.substr(1));char c=name[0];
    if((c=='x' || c=='w') && n<=30)return{name,int(n),c=='x'?64u:32u};
    unsigned bits=c=='v'||c=='q'?128:c=='d'?64:c=='s'?32:c=='h'?16:c=='b'?8:0;
    if(n>31 || !bits)throw std::invalid_argument("invalid register: "+name);
    return{name,33+int(n),bits};
}
inline unsigned __int128 masked(unsigned __int128 v,unsigned bits){return bits==128?v:v&((static_cast<unsigned __int128>(1)<<bits)-1);}
inline std::string location(uint64_t address,const Info& info) {
    std::string row;emit::kv_hex(row,"address",address);
    for(const auto& item:info.modules) {
        const auto& module=item.second;
        if(address>=module.base && address-module.base<module.size) {
            emit::kv_str(row+=",","module",module.name);
            emit::kv_hex(row+=",","module_base",module.base);emit::kv_hex(row+=",","offset",address-module.base);
            return "{"+row+"}";
        }
    }
    return "{"+row+",\"module\":null,\"module_base\":null,\"offset\":null}";
}
inline std::string register_values(const Registers& values,const std::vector<Register>& selected,bool unknown) {
    std::string row;
    for(const auto& r:selected) {
        if(!row.empty())row+=",";
        if(r.slot<0 || (!unknown && values[r.slot].known))
            emit::kv_hex128(row,r.name.c_str(),r.slot<0?0:masked(values[r.slot].bits,r.bits));
        else {emit::esc_append(row,r.name.c_str());row+=":null";}
    }
    return "{"+row+"}";
}
} // namespace traceq::stream::query_detail
