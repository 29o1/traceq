#pragma once
#include <traceq/write_stream.h>
#include <array>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace traceq::stream {
struct Value { unsigned __int128 bits=0; bool known=false; };
using Registers=std::array<Value,writes::REGISTER_COUNT>;
struct Exit { uint64_t target=0,transfer=0,expected_return=0; };
struct Group {
    uint64_t seq=0,pc=0,word=0;
    Registers pre{},post{};
    std::vector<writes::Event> accesses;
    bool committed=false,gap=false;
    Exit exit{};
    bool reentered=false;
    uint64_t exit_seq=0,gap_count=0;
    uint64_t gap_reason_mask=0;
};
struct Module { uint64_t base=0,size=0;std::string name; };
struct Info {
    writes::Header header{};
    uint64_t instructions=0,reads=0,writes=0,gaps=0,commits=0;
    uint64_t unknown_reads=0;
    bool unpositioned_gap=false;
    bool chunked=false;
    bool boundary_capture=false;
    bool external_followed=false;
    uint64_t exits=0,reentries=0;
    std::unordered_map<uint64_t,Module> modules;
    std::array<uint64_t,7> gap_reasons{};
    std::unordered_map<std::string,uint64_t> unsupported_mnemonics;
    std::unordered_map<uint64_t,std::string> sites;
    std::unordered_map<uint64_t,uint32_t> words;
};
bool read(const std::string& path,Info& info,
          const std::function<void(const Group&,const Info&)>& callback,std::string& error);
bool is_state_stream(int argc,char** argv);
int command(const std::string& name,int argc,char** argv);
int context_command(int argc,char** argv);
} // namespace traceq::stream
