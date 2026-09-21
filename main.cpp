#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#include <cctype>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
using socket_t = SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
#endif

namespace fs=std::filesystem;
using namespace std::chrono_literals;

#ifdef _WIN32
static void close_socket(socket_t s){closesocket(s);}
#else
static void close_socket(socket_t s){close(s);}
#endif

static std::string hex64(const std::array<unsigned char,32>& a){
    std::ostringstream o;
    for(auto c:a)o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)c;
    return o.str();
}

// Compact SHA-256 implementation.
class SHA256 {
    uint32_t h[8]={
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,
        0x1f83d9ab,0x5be0cd19
    };
    static uint32_t rotr(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
    void block(const unsigned char* p){
        static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
        0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
        0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
        0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
        0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
        0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(uint32_t(p[4*i])<<24)|(uint32_t(p[4*i+1])<<16)|(uint32_t(p[4*i+2])<<8)|p[4*i+3];
        for(int i=16;i<64;i++){
            uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],x=h[7];
        for(int i=0;i<64;i++){
            uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1=x+S1+ch+k[i]+w[i];
            uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t t2=S0+maj;
            x=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=x;
    }
public:
    static std::string hash(const std::vector<unsigned char>& data){
        SHA256 s; uint64_t bits=(uint64_t)data.size()*8; size_t n=data.size();
        size_t total=((n+9+63)/64)*64; std::vector<unsigned char> p(total,0);
        std::copy(data.begin(),data.end(),p.begin()); p[n]=0x80;
        for(int i=0;i<8;i++)p[total-1-i]=(bits>>(8*i))&255;
        for(size_t i=0;i<total;i+=64)s.block(p.data()+i);
        std::array<unsigned char,32> out{};
        for(int i=0;i<8;i++)for(int j=0;j<4;j++)out[i*4+j]=(s.h[i]>>(24-8*j))&255;
        return hex64(out);
    }
};

struct Node { std::string id,url; bool healthy=true; };
struct Chunk { int index; std::string hash; size_t size; };
struct FileMeta { std::string id,name,created; uint64_t size=0; int version=1; std::vector<Chunk> chunks; };

static std::string json_escape(const std::string&s){
    std::string o;
    for(char c:s){if(c=='"'||c=='\\')o+='\\'; if(c=='\n')o+="\\n"; else if(c!='\r')o+=c;}
    return o;
}
static std::string random_id(){
    static std::atomic<uint64_t> n{0};
    return std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count())+"-"+std::to_string(++n);
}

class Store {
    fs::path root; mutable std::mutex m;
public:
    explicit Store(fs::path r):root(std::move(r)){fs::create_directories(root/"chunks");fs::create_directories(root/"meta");}
    bool put(const std::vector<unsigned char>&d,std::string h){
        std::lock_guard<std::mutex>g(m); fs::path p=root/"chunks"/h;
        if(fs::exists(p))return true; std::ofstream f(p,std::ios::binary); if(!f)return false; f.write((char*)d.data(),d.size()); return !!f;
    }
    std::optional<std::vector<unsigned char>> get(const std::string&h){
        if(h.size()!=64)return {};
        std::lock_guard<std::mutex>g(m); std::ifstream f(root/"chunks"/h,std::ios::binary);
        if(!f)return {}; return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),{});
    }
    bool has(const std::string&h){std::lock_guard<std::mutex>g(m);return fs::exists(root/"chunks"/h);}
    size_t count(){std::lock_guard<std::mutex>g(m);size_t n=0;for(auto&e:fs::directory_iterator(root/"chunks"))if(e.is_regular_file())n++;return n;}
    void save(const FileMeta&f){
        std::lock_guard<std::mutex>g(m);std::ofstream o(root/"meta"/(f.id+".meta"));
        o<<f.id<<"\n"<<f.name<<"\n"<<f.created<<"\n"<<f.size<<"\n"<<f.version<<"\n"<<f.chunks.size()<<"\n";
        for(auto&c:f.chunks)o<<c.index<<" "<<c.hash<<" "<<c.size<<"\n";
    }
    std::vector<FileMeta> load(){
        std::lock_guard<std::mutex>g(m);std::vector<FileMeta>v;
        for(auto&e:fs::directory_iterator(root/"meta")){
            if(!e.is_regular_file())continue;std::ifstream in(e.path());FileMeta f;size_t n;
            if(!(in>>f.id))continue;in.ignore();std::getline(in,f.name);std::getline(in,f.created);
            in>>f.size>>f.version>>n;
            for(size_t i=0;i<n;i++){Chunk c;in>>c.index>>c.hash>>c.size;f.chunks.push_back(c);}v.push_back(f);
        }return v;
    }
};

struct HttpReq { std::string method,path,body; std::map<std::string,std::string> headers; };
struct HttpResp { int code=200; std::string type="application/json",body; };

static bool recv_all(socket_t s,std::string&out){
    char buf[8192]; out.clear();
    while(true){
        int n=recv(s,buf,sizeof(buf),0); if(n<=0)break; out.append(buf,n);
        auto pos=out.find("\r\n\r\n"); if(pos!=std::string::npos){
            size_t cl=0;auto h=out.substr(0,pos);
            auto p=h.find("Content-Length:");
            if(p!=std::string::npos){auto e=h.find("\r\n",p);cl=std::stoull(h.substr(p+15,e-p-15));}
            if(out.size()>=pos+4+cl)break;
        }
        if(out.size()>20*1024*1024)return false;
    }return !out.empty();
}
static HttpReq parse_req(const std::string&r){
    HttpReq q;auto p=r.find("\r\n\r\n");std::string h=r.substr(0,p),b=r.substr(p+4);std::istringstream in(h);std::string line;
    std::getline(in,line);if(!line.empty()&&line.back()=='\r')line.pop_back();std::istringstream x(line);x>>q.method>>q.path;
    while(std::getline(in,line)){if(line.size()&&line.back()=='\r')line.pop_back();auto k=line.find(':');if(k!=std::string::npos){std::string a=line.substr(0,k),v=line.substr(k+1);while(!v.empty()&&v[0]==' ')v.erase(v.begin());q.headers[a]=v;}}
    q.body=b;return q;
}
static void send_resp(socket_t s,const HttpResp&r){
    std::ostringstream o;o<<"HTTP/1.1 "<<r.code<<" "<<(r.code==200?"OK":r.code==201?"Created":r.code==404?"Not Found":r.code==503?"Service Unavailable":"Bad Request")<<"\r\nContent-Type: "<<r.type<<"\r\nContent-Length: "<<r.body.size()<<"\r\nConnection: close\r\n\r\n";
    auto h=o.str();send(s,h.data(),(int)h.size(),0);if(!r.body.empty())send(s,r.body.data(),(int)r.body.size(),0);
}
static std::string url_host(const std::string&u,int&port){
    std::string x=u;auto p=x.find("://");if(p!=std::string::npos)x=x.substr(p+3);auto c=x.rfind(':');if(c==std::string::npos){port=80;return x;}port=std::stoi(x.substr(c+1));return x.substr(0,c);
}
static std::optional<HttpResp> http_call(const std::string&url,const std::string&method,const std::string&body="",const std::string&type="application/octet-stream"){
    auto p=url.find("://");std::string rest=p==std::string::npos?url:url.substr(p+3);auto slash=rest.find('/');std::string hostport=slash==std::string::npos?rest:rest.substr(0,slash),path=slash==std::string::npos?"/":rest.substr(slash);
    int port=80;auto c=hostport.rfind(':');std::string host=hostport;if(c!=std::string::npos){port=std::stoi(hostport.substr(c+1));host=hostport.substr(0,c);}
    addrinfo hints{},*res=nullptr;hints.ai_socktype=SOCK_STREAM;hints.ai_family=AF_UNSPEC;std::string ps=std::to_string(port);
    if(getaddrinfo(host.c_str(),ps.c_str(),&hints,&res)!=0)return {};
    socket_t s=socket(res->ai_family,res->ai_socktype,res->ai_protocol);if(s<0){freeaddrinfo(res);return {};}
    struct timeval tv{3,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv,sizeof(tv));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char*)&tv,sizeof(tv));
    if(connect(s,res->ai_addr,(int)res->ai_addrlen)!=0){close_socket(s);freeaddrinfo(res);return {};}
    freeaddrinfo(res);std::ostringstream q;q<<method<<" "<<path<<" HTTP/1.1\r\nHost: "<<host<<"\r\nConnection: close\r\nContent-Type: "<<type<<"\r\nContent-Length: "<<body.size()<<"\r\n\r\n";auto h=q.str();send(s,h.data(),(int)h.size(),0);if(!body.empty())send(s,body.data(),(int)body.size(),0);
    std::string raw;recv_all(s,raw);close_socket(s);auto e=raw.find("\r\n\r\n");if(e==std::string::npos)return {};std::istringstream st(raw.substr(0,e));std::string line;std::getline(st,line);int code=0;std::istringstream(line)>>line>>code>>line;HttpResp rr;rr.code=code;rr.body=raw.substr(e+4);auto ct=st.str();rr.type=type;return rr;
}

class Server {
    std::string id,self;int port;Store store;std::vector<Node>nodes;std::mutex m;std::map<std::string,FileMeta>files;
    static constexpr size_t CHUNK=1024*1024;
public:
    Server(std::string i,int p,fs::path d,std::vector<std::string>peers):id(std::move(i)),port(p),store(std::move(d)){
        self="http://127.0.0.1:"+std::to_string(port);nodes.push_back({id,self,true});
        int k=1;for(auto&p:peers)if(!p.empty())nodes.push_back({"peer"+std::to_string(k++),p,true});
        for(auto&f:store.load())files[f.id]=f;
    }
    void health_loop(){
        while(true){std::this_thread::sleep_for(3s);std::lock_guard<std::mutex>g(m);
            for(auto&n:nodes){if(n.id==id){n.healthy=true;continue;}auto r=http_call(n.url+"/internal/health","GET");n.healthy=r&&r->code==200;}
        }
    }
    bool put_replicated(const std::string&hash,const std::vector<unsigned char>&data){
        std::vector<Node>ns;{std::lock_guard<std::mutex>g(m);for(auto n:nodes)if(n.healthy)ns.push_back(n);}
        int ok=0;for(auto&n:ns){
            if(n.id==id){if(store.put(data,hash))ok++;}
            else{
                std::string payload=hash+"\n"+std::string((char*)data.data(),data.size());
                auto r=http_call(n.url+"/internal/chunk","POST",payload,"application/octet-stream");
                if(r&&r->code==201)ok++;
            }
            if(ok>=3)break;
        }return ok>0;
    }
    std::optional<std::vector<unsigned char>> get_chunk(const std::string&h){
        if(auto x=store.get(h))return x;
        std::vector<Node>ns;{std::lock_guard<std::mutex>g(m);for(auto n:nodes)if(n.healthy)ns.push_back(n);}
        for(auto&n:ns)if(n.id!=id){auto r=http_call(n.url+"/internal/chunk/"+h,"GET");if(r&&r->code==200)return std::vector<unsigned char>(r->body.begin(),r->body.end());}
        return {};
    }
    std::string files_json(){std::lock_guard<std::mutex>g(m);std::ostringstream o;o<<"[";bool first=true;for(auto&[k,f]:files){if(!first)o<<",";first=false;o<<"{\"id\":\""<<json_escape(f.id)<<"\",\"name\":\""<<json_escape(f.name)<<"\",\"size\":"<<f.size<<",\"version\":"<<f.version<<"}";}return o.str()+"]";}
    std::string cluster_json(){std::lock_guard<std::mutex>g(m);std::ostringstream o;o<<"[";for(size_t i=0;i<nodes.size();i++){if(i)o<<",";auto&n=nodes[i];o<<"{\"id\":\""<<n.id<<"\",\"url\":\""<<n.url<<"\",\"healthy\":"<<(n.healthy?"true":"false")<<",\"chunks\":"<<(n.id==id?store.count():0)<<"}";}return o.str()+"]";}
    HttpResp handle(const HttpReq&q){
        if(q.method=="GET"&&q.path=="/internal/health")return {200,"application/json","{\"status\":\"ok\"}"};
        if(q.method=="GET"&&q.path=="/api/cluster")return {200,"application/json",cluster_json()};
        if(q.method=="GET"&&q.path=="/api/files")return {200,"application/json",files_json()};
        if(q.method=="POST"&&q.path=="/api/files"){
            std::string name="upload.bin";auto it=q.headers.find("X-Filename");if(it!=q.headers.end()&&!it->second.empty())name=it->second;
            FileMeta f;f.id=random_id();f.name=fs::path(name).filename().string();f.size=q.body.size();f.created=std::to_string(std::time(nullptr));
            for(size_t p=0;p<q.body.size();p+=CHUNK){size_t e=std::min(q.body.size(),p+CHUNK);std::vector<unsigned char>d(q.body.begin()+p,q.body.begin()+e);std::string h=SHA256::hash(d);if(!put_replicated(h,d))return {503,"application/json","{\"error\":\"replication failed\"}"};f.chunks.push_back({(int)(p/CHUNK),h,d.size()});}
            {std::lock_guard<std::mutex>g(m);files[f.id]=f;}store.save(f);
            std::ostringstream o;o<<"{\"id\":\""<<f.id<<"\",\"name\":\""<<json_escape(f.name)<<"\",\"size\":"<<f.size<<",\"chunks\":"<<f.chunks.size()<<"}";
            return {201,"application/json",o.str()};
        }
        const std::string pre="/api/files/";
        if(q.path.rfind(pre,0)==0){
            std::string rest=q.path.substr(pre.size());
            auto slash=rest.find('/');
            std::string fid=slash==std::string::npos?rest:rest.substr(0,slash);
            FileMeta f;
            {
                std::lock_guard<std::mutex> g(m);
                auto it=files.find(fid);
                if(it==files.end())return {404,"application/json","{\"error\":\"file not found\"}"};
                f=it->second;
            }
            if(slash!=std::string::npos&&rest.substr(slash)=="/snapshot"&&q.method=="POST"){
                std::lock_guard<std::mutex> g(m);
                auto it=files.find(fid);
                if(it==files.end())return {404,"application/json","{\"error\":\"file not found\"}"};
                it->second.version++;
                store.save(it->second);
                return {201,"application/json","{\"snapshot_version\":"+std::to_string(it->second.version)+"}"};
            }
            if(q.method=="GET"&&slash==std::string::npos){
                std::string all;
                for(auto&c:f.chunks){
                    auto d=get_chunk(c.hash);
                    if(!d)return {503,"application/json","{\"error\":\"chunk unavailable\"}"};
                    all.append((char*)d->data(),d->size());
                }
                return {200,"application/octet-stream",all};
            }
        }
        if(q.method=="POST"&&q.path=="/internal/chunk"){
            auto p=q.body.find('\n');if(p==std::string::npos)return {400,"text/plain","bad chunk"};
            std::string h=q.body.substr(0,p),data=q.body.substr(p+1);std::vector<unsigned char>d(data.begin(),data.end());if(SHA256::hash(d)!=h)return {400,"text/plain","hash mismatch"};return store.put(d,h)?HttpResp{201,"application/json","{\"ok\":true}"}:HttpResp{500,"text/plain","store error"};
        }
        const std::string cp="/internal/chunk/";if(q.method=="GET"&&q.path.rfind(cp,0)==0){auto d=store.get(q.path.substr(cp.size()));if(!d)return {404,"text/plain","not found"};return {200,"application/octet-stream",std::string((char*)d->data(),d->size())};}
        if(q.method=="GET"&&q.path=="/")return {200,"text/html",dashboard()};
        return {404,"application/json","{\"error\":\"not found\"}"};
    }
    static std::string dashboard(){return R"HTML(<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Distributed Storage</title><style>body{font-family:Arial;max-width:1000px;margin:30px auto;padding:0 15px;background:#f4f6fa}.card{background:#fff;padding:20px;margin:15px 0;border-radius:12px;box-shadow:0 2px 10px #0001}button{padding:9px 14px}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #ddd}</style></head><body><h1>Distributed Fault-Tolerant File Storage</h1><div class=card><input id=f type=file><button onclick=up()>Upload</button><pre id=r></pre></div><div class=card><h2>Cluster</h2><button onclick=load()>Refresh</button><div id=n></div></div><div class=card><h2>Files</h2><div id=x></div></div><script>async function up(){let f=document.getElementById('f').files[0];if(!f)return;let r=await fetch('/api/files',{method:'POST',headers:{'X-Filename':f.name},body:await f.arrayBuffer()});document.getElementById('r').textContent=await r.text();load()}async function load(){let n=await(await fetch('/api/cluster')).json();document.getElementById('n').innerHTML='<table><tr><th>Node</th><th>Status</th><th>Chunks</th></tr>'+n.map(a=>`<tr><td>${a.id}</td><td>${a.healthy?'HEALTHY':'DOWN'}</td><td>${a.chunks}</td></tr>`).join('')+'</table>';let f=await(await fetch('/api/files')).json();document.getElementById('x').innerHTML='<table><tr><th>Name</th><th>Size</th><th>Version</th><th>Download</th></tr>'+f.map(a=>`<tr><td>${a.name}</td><td>${a.size}</td><td>${a.version}</td><td><a href="/api/files/${a.id}">Download</a></td></tr>`).join('')+'</table>'}load()</script></body></html>)HTML";}
    void run_socket(socket_t s){std::string raw;if(recv_all(s,raw)){auto q=parse_req(raw);auto r=handle(q);send_resp(s,r);}close_socket(s);}
public:
    void run(){
#ifdef _WIN32
        WSADATA w;WSAStartup(MAKEWORD(2,2),&w);
#endif
        socket_t s=socket(AF_INET,SOCK_STREAM,0);int yes=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
        sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_ANY);a.sin_port=htons(port);
        if(bind(s,(sockaddr*)&a,sizeof(a))<0){std::cerr<<"bind failed\n";return;}if(listen(s,64)<0){std::cerr<<"listen failed\n";return;}
        std::cout<<id<<" listening on "<<port<<"\n";std::thread(&Server::health_loop,this).detach();
        while(true){sockaddr_in c{};socklen_t n=sizeof(c);socket_t cs=accept(s,(sockaddr*)&c,&n);if(cs>=0)std::thread(&Server::run_socket,this,cs).detach();}
    }
};

int main(int argc,char**argv){
    std::string id="node1",data="./data/node1";int port=8081;std::vector<std::string>peers;
    for(int i=1;i<argc;i++){std::string a=argv[i];auto val=[&](std::string k){return i+1<argc&&a==k?std::string(argv[++i]):std::string();};std::string v;
        if(!(v=val("--id")).empty())id=v;else if(!(v=val("--port")).empty())port=std::stoi(v);else if(!(v=val("--data")).empty())data=v;else if(!(v=val("--peers")).empty()){std::stringstream ss(v);while(std::getline(ss,v,','))peers.push_back(v);}
    }
    Server s(id,port,data,peers);s.run();
}
