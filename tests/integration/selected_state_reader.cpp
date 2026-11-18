// Compare sparse replay with full replay, including all65 slots and gaps.
// Historical comparison only. Build with the isolated reference state_stream.cpp
// and -Iexperiments/retired_cpp_product108/cli/src -Icli/include; pass trace paths.
#include "state_stream.h"
#include <deque>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
using namespace traceq::stream;
static void require(bool v,const char* why){if(!v)throw std::runtime_error(why);}
static uint64_t mix(uint64_t h,uint64_t v){return (h^v)*1099511628211ull;}
static uint64_t facts(uint64_t h,const Group& g){
 for(auto x:{g.seq,g.pc,g.word,uint64_t(g.committed),uint64_t(g.gap),g.exit.target,g.exit.transfer,g.exit.expected_return,uint64_t(g.reentered),g.exit_seq,g.gap_count,g.gap_reason_mask,uint64_t(g.accesses.size())})h=mix(h,x);
 for(const auto&e:g.accesses)for(auto x:{e.kind,e.seq,e.pc,e.address,e.size,e.low,e.high,e.detail})h=mix(h,x);return h;
}
static void same_registers(const Registers&a,const Registers&b){for(unsigned i=0;i<traceq::writes::REGISTER_COUNT;++i){require(a.known[i]==b.known[i],"known-state changed");if(a.known[i])require(a.bits[i]==b.bits[i],"register value changed");}}
static void same_group(const Group&a,const Group&b){require(facts(0,a)==facts(0,b),"structural/access facts changed");same_registers(a.pre,b.pre);same_registers(a.post,b.post);require(a.pre_observed==b.pre_observed&&a.post_observed==b.post_observed,"observation masks changed");}
static void same_info(const Info&a,const Info&b){
 require(a.instructions==b.instructions&&a.reads==b.reads&&a.writes==b.writes&&a.gaps==b.gaps&&a.commits==b.commits&&a.unknown_reads==b.unknown_reads&&a.exits==b.exits&&a.reentries==b.reentries,"counters changed");
 require(a.unpositioned_gap==b.unpositioned_gap&&a.chunked==b.chunked&&a.boundary_capture==b.boundary_capture&&a.external_followed==b.external_followed,"stream flags changed");
 const auto&x=a.header;const auto&y=b.header;require(x.code_base==y.code_base&&x.code_size==y.code_size&&x.data_base==y.data_base&&x.data_size==y.data_size&&x.thread_id==y.thread_id&&x.profile==y.profile,"header changed");
 require(a.sites==b.sites&&a.words==b.words&&a.gap_reasons==b.gap_reasons&&a.unsupported_mnemonics==b.unsupported_mnemonics&&a.modules.size()==b.modules.size(),"metadata changed");
 for(const auto&m:a.modules){const auto&n=b.modules.at(m.first);require(m.second.base==n.base&&m.second.size==n.size&&m.second.name==n.name,"module changed");}
}
int main(int argc,char**argv){try{require(argc>1,"pass trace paths");for(int arg=1;arg<argc;++arg){
 std::map<uint64_t,Group> expected;std::deque<Group> recent;Info full,sparse,empty;std::string ef,es,ee;uint64_t hf=0,hs=0,he=0,groups=0,selected=0;unsigned gaps=0;uint64_t next_gap_neighbor=~uint64_t(0);
 bool vf=read(argv[arg],full,[&](const Group&g,const Info&){hf=facts(hf,g);++groups;if(g.seq<3||g.seq%257==0||g.seq==next_gap_neighbor)expected[g.seq]=g;if(g.gap&&gaps++<32){for(const auto&p:recent)expected[p.seq]=p;expected[g.seq]=g;next_gap_neighbor=g.seq+1;}recent.push_back(g);if(recent.size()>3)recent.pop_front();},ef);
 for(const auto&g:recent)expected[g.seq]=g;
 bool vs=read_selected(argv[arg],sparse,[&](const Group&g,const Info&){hs=facts(hs,g);auto e=expected.find(g.seq);if(e!=expected.end()){same_group(e->second,g);++selected;}else{for(bool v:g.pre.known)require(!v,"unselected pre marked known");for(bool v:g.post.known)require(!v,"unselected post marked known");require(g.pre_observed==std::array<uint64_t,2>{}&&g.post_observed==std::array<uint64_t,2>{},"unselected observation leaked");}},es,[&](uint64_t s){return expected.count(s)!=0;});
 require(vf==vs&&ef==es,"selected validity/error changed");require(selected==expected.size()&&hf==hs,"selected groups missing or facts changed");same_info(full,sparse);
 bool ve=read_selected(argv[arg],empty,[&](const Group&g,const Info&){he=facts(he,g);for(bool v:g.pre.known)require(!v,"empty selection pre");for(bool v:g.post.known)require(!v,"empty selection post");require(g.pre_observed==std::array<uint64_t,2>{}&&g.post_observed==std::array<uint64_t,2>{},"empty selection masks");},ee,[](uint64_t){return false;});
 require(vf==ve&&ef==ee&&hf==he,"empty selection skipped validation/facts");same_info(full,empty);
 std::cout<<argv[arg]<<" groups="<<groups<<" selected="<<selected<<" valid="<<vf<<" PASS\n";
 }}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
