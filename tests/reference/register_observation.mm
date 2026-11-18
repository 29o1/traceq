// Isolated C++ reference only; check_registers.py defaults to the Rust runtime.
// Same-context differential check of optimized observation vs scalar Reference.
// This includes the implementation so its private cache and emitter are tested
// without adding a test API to the capture library.
#ifndef TRACEQ_OBSERVER_SOURCE
#define TRACEQ_OBSERVER_SOURCE "../../experiments/retired_cpp_product108/capture/traceq/src/WriteStream.cpp"
#endif
#include TRACEQ_OBSERVER_SOURCE
#include <algorithm>
#include <array>
#include <cstdio>
#include <random>
#include <stdexcept>
#include <vector>

using Bits=unsigned __int128;
struct Step { GumCpuContext cpu{}; bool gap=false,restart=false,unchanged=false; };
struct Observations {
    std::vector<traceq::writes::Event> events;
    std::vector<std::array<Bits,65>> states;
};
static void require(bool condition,const char* message) {
    if(!condition)throw std::runtime_error(message);
}
static void set_slot(GumCpuContext& c,unsigned slot,Bits value) {
    if(slot<29)c.x[slot]=uint64_t(value);
    else if(slot==29)c.fp=uint64_t(value);
    else if(slot==30)c.lr=uint64_t(value);
    else if(slot==31)c.sp=uint64_t(value);
    else if(slot==32)c.nzcv=uint64_t(value);
    else memcpy(c.v[slot-33].q,&value,16);
}
static std::vector<Step> contexts() {
    std::vector<Step> steps;GumCpuContext cpu{};
    auto save=[&](bool gap=false,bool restart=false,bool unchanged=false){steps.push_back({cpu,gap,restart,unchanged});};
    save();save(false,false,true);save(true);save(false,true);
    // Every group boundary and the last SIMD slot; upper bits change alone.
    for(unsigned slot=0;slot<65;++slot) {
        set_slot(cpu,slot,slot<33?Bits(0x8000000000000001ull+slot):(Bits(1)<<(64+slot%64))|0x7ff8000000000001ull);
        save();save(false,false,true);
        if(slot>=33){set_slot(cpu,slot,(Bits(1)<<127)|0x7ff8000000000001ull);save();}
    }
    const Bits patterns[]={0,~Bits(0),Bits(1)<<127,Bits(1)<<63,
                           (Bits(0x7ff8123456789abcull)<<64)|0x8000000000000000ull};
    for(Bits value:patterns) {
        for(unsigned slot=0;slot<65;++slot)set_slot(cpu,slot,value);
        save();save(false,false,true);save(true);save(false,true);
    }
    std::mt19937_64 random(0x747261636571);
    for(unsigned n=0;n<1536;++n) {
        const bool unchanged=n%7==0;
        if(!unchanged) {
            unsigned count=n%31==0?65:n%11==0?8:1;
            for(unsigned i=0;i<count;++i) {
                unsigned slot=count==65?i:unsigned(random()%65);
                Bits value=Bits(random())|(Bits(random())<<64);set_slot(cpu,slot,value);
            }
        }
        save(n%97==0,n%127==0,unchanged && n%97!=0 && n%127!=0);
    }
    return steps;
}
static Observations run(const std::vector<Step>& steps,TraceqObservation mode) {
    FILE* file=tmpfile();require(file!=nullptr,"tmpfile failed");
    session.out=file;session.records=nullptr;session.failed=false;
    session.observation=mode;session.registers_complete=false;
    memset(session.state_known,0,sizeof session.state_known);
    Observations result;Plan plan;plan.pc=0x1000;
    for(size_t n=0;n<steps.size();++n) {
        const auto& step=steps[n];plan.seq=n;
        if(step.restart){memset(session.state_known,0,sizeof session.state_known);session.registers_complete=false;}
        if(step.gap)gap(n,plan.pc,traceq::writes::UNSUPPORTED);
        const long before=ftell(file);
        GumCpuContext cpu=step.cpu;
        state_delta(&cpu,&plan,n%2?traceq::writes::REG_POST:traceq::writes::REG_PRE);
        require(std::all_of(std::begin(session.state_known),std::end(session.state_known),[](bool v){return v;}),"lost register validity");
        const long bytes=ftell(file)-before;
        if(!n || step.gap || step.restart)require(bytes==65*64,"resynchronization did not record all 65 slots");
        if(step.unchanged)require(bytes==0,"unchanged snapshot emitted a delta");
        std::array<Bits,65> state;std::copy(std::begin(session.state),std::end(session.state),state.begin());
        result.states.push_back(state);
    }
    require(!session.failed && fflush(file)==0,"observer write failed");
    rewind(file);unsigned char bytes[64];
    while(fread(bytes,1,sizeof bytes,file)==sizeof bytes) {
        result.events.push_back({get64(bytes),get64(bytes+8),get64(bytes+16),get64(bytes+24),
                                 get64(bytes+32),get64(bytes+40),get64(bytes+48),get64(bytes+56)});
    }
    require(feof(file) && !ferror(file),"event read failed");
    fclose(file);session.out=nullptr;
    return result;
}
int main() {
    try {
        auto steps=contexts();auto reference=run(steps,TraceqObservation::Reference);
        for(auto mode:{TraceqObservation::Banked,TraceqObservation::Fused}) {
            auto actual=run(steps,mode);
            require(actual.states==reference.states,"65-slot cache states differ from Reference");
            require(actual.events.size()==reference.events.size(),"register event count differs from Reference");
            static_assert(sizeof(traceq::writes::Event)==64,"event layout changed");
            require(memcmp(actual.events.data(),reference.events.data(),actual.events.size()*64)==0,
                    "register event values/order differ from Reference");
        }
        printf("PASS %zu snapshots, %zu events per mode; all 65 slots, gaps, restarts, unchanged groups and bit patterns\n",
               steps.size(),reference.events.size());return 0;
    } catch(const std::exception& e) {fprintf(stderr,"%s\n",e.what());return 1;}
}
