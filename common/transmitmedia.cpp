// Medium concretizations

// Just for formality. This file should be used 
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <iterator>
#include <map>
#include <srt.h>

#include "netinet_any.h"
#include "appcommon.hpp"
#include "socketoptions.hpp"
#include "uriparser.hpp"
#include "transmitmedia.hpp"
#include "srt_compat.h"

using namespace std;

bool transmit_verbose = false;
std::ostream* transmit_cverb = nullptr;
volatile bool transmit_throw_on_interrupt = false;
int transmit_bw_report = 0;
unsigned transmit_stats_report = 0;
size_t transmit_chunk_size = SRT_LIVE_DEF_PLSIZE;

class FileSource: public Source
{
    ifstream ifile;
    string filename_copy;
public:

    FileSource(const string& path): ifile(path, ios::in | ios::binary), filename_copy(path)
    {
        if ( !ifile )
            throw std::runtime_error(path + ": Can't open file for reading");
    }

    bytevector Read(size_t chunk) override
    {
        bytevector data(chunk);
        ifile.read(data.data(), chunk);
        size_t nread = ifile.gcount();
        if ( nread < data.size() )
            data.resize(nread);

        if ( data.empty() )
            throw ReadEOF(filename_copy);
        return data;
    }

    bool IsOpen() override { return bool(ifile); }
    bool End() override { return ifile.eof(); }
    //~FileSource() { ifile.close(); }
};

class FileTarget: public Target
{
    ofstream ofile;
public:

    FileTarget(const string& path): ofile(path, ios::out | ios::trunc | ios::binary) {}

    void Write(const bytevector& data) override
    {
        ofile.write(data.data(), data.size());
    }

    bool IsOpen() override { return !!ofile; }
    bool Broken() override { return !ofile.good(); }
    //~FileTarget() { ofile.close(); }
    void Close() override { ofile.close(); }
};

template <class Iface> struct File;
template <> struct File<Source> { typedef FileSource type; };
template <> struct File<Target> { typedef FileTarget type; };

template <class Iface>
Iface* CreateFile(const string& name) { return new typename File<Iface>::type (name); }


template <class PerfMonType>
void PrintSrtStats(int sid, const PerfMonType& mon)
{
    cout << "======= SRT STATS: sid=" << sid << endl;
    cout << "PACKETS SENT: " << mon.pktSent << " RECEIVED: " << mon.pktRecv << endl;
    cout << "LOST PKT SENT: " << mon.pktSndLoss << " RECEIVED: " << mon.pktRcvLoss << endl;
    cout << "REXMIT SENT: " << mon.pktRetrans << " RECEIVED: " << mon.pktRcvRetrans << endl;
    cout << "RATE SENDING: " << mon.mbpsSendRate << " RECEIVING: " << mon.mbpsRecvRate << endl;
    cout << "BELATED RECEIVED: " << mon.pktRcvBelated << " AVG TIME: " << mon.pktRcvAvgBelatedTime << endl;
    cout << "REORDER DISTANCE: " << mon.pktReorderDistance << endl;
    cout << "WINDOW: FLOW: " << mon.pktFlowWindow << " CONGESTION: " << mon.pktCongestionWindow << " FLIGHT: " << mon.pktFlightSize << endl;
    cout << "RTT: " << mon.msRTT << "ms  BANDWIDTH: " << mon.mbpsBandwidth << "Mb/s\n";
    cout << "BUFFERLEFT: SND: " << mon.byteAvailSndBuf << " RCV: " << mon.byteAvailRcvBuf << endl;
}


void SrtCommon::InitParameters(string host, string path, map<string,string> par)
{
    // Application-specific options: mode, blocking, timeout, adapter
    if ( transmit_verbose )
    {
        cout << "HOST:" << host << " PATH:" << path << " Parameters:\n";
        for (map<string,string>::iterator i = par.begin(); i != par.end(); ++i)
        {
            cout << "\t" << i->first << " = '" << i->second << "'\n";
        }
    }

    if (path != "")
    {
        // Special case handling of an unusual specification.

        if (path.substr(0, 2) != "//")
        {
            Error("Path specification not supported for SRT (use // in front for special cases)");
        }

        path = path.substr(2);

        if (path == "group")
        {
            // Group specified, check type.
            m_group_type = par["type"];
            if (m_group_type == "")
            {
                Error("With //group, the group 'type' must be specified.");
            }

            if (m_group_type != "redundancy")
            {
                Error("With //group, only type=redundancy is currently supported");
            }

            vector<string> nodes;
            Split(par["nodes"], ',', back_inserter(nodes));

            if (nodes.empty())
            {
                Error("With //group, 'nodes' must specify comma-separated host:port specs.");
            }

            // Check if correctly specified
            for (string& hostport: nodes)
            {
                if (hostport == "")
                    continue;
                UriParser check(hostport, UriParser::EXPECT_HOST);
                if (check.host() == "" || check.port() == "")
                {
                    Error("With //group, 'nodes' must specify comma-separated host:port specs.");
                }

                if (check.portno() <= 1024)
                {
                    Error("With //group, every node in 'nodes' must have port >1024");
                }

                m_group_nodes.push_back(Connection(check.host(), check.portno()));
            }

            par.erase("type");
            par.erase("nodes");
        }
    }

    m_mode = "default";
    if ( par.count("mode") )
        m_mode = par.at("mode");

    if ( m_mode == "default" )
    {
        // Use the following convention:
        // 1. Server for source, Client for target
        // 2. If host is empty, then always server.
        if ( host == "" && m_group_nodes.empty() )
            m_mode = "listener";
        //else if ( !dir_output )
        //m_mode = "server";
        else
            m_mode = "caller";
    }

    if ( m_mode == "client" )
        m_mode = "caller";
    else if ( m_mode == "server" )
        m_mode = "listener";

    if (m_mode == "listener" && !m_group_nodes.empty())
    {
        Error("Multiple nodes (redundant links) only supported in CALLER (client) mode.");
    }

    par.erase("mode");

    if ( par.count("blocking") )
    {
        m_blocking_mode = !false_names.count(par.at("blocking"));
        par.erase("blocking");
    }

    if ( par.count("timeout") )
    {
        m_timeout = stoi(par.at("timeout"), 0, 0);
        par.erase("timeout");
    }

    if ( par.count("adapter") )
    {
        m_adapter = par.at("adapter");
        par.erase("adapter");
    }
    else if (m_mode == "listener")
    {
        // For listener mode, adapter is taken from host,
        // if 'adapter' parameter is not given
        m_adapter = host;
    }

    if ( par.count("tsbpd") && false_names.count(par.at("tsbpd")) )
    {
        m_tsbpdmode = false;
    }

    if (par.count("port"))
    {
        m_outgoing_port = stoi(par.at("port"), 0, 0);
        par.erase("port");
    }

    // That's kinda clumsy, but it must rely on the defaults.
    // Default mode is live, so check if the file mode was enforced
    if (par.count("transtype") == 0 || par["transtype"] != "file")
    {
        // If the Live chunk size was nondefault, enforce the size.
        if (transmit_chunk_size != SRT_LIVE_DEF_PLSIZE)
        {
            if (transmit_chunk_size > SRT_LIVE_MAX_PLSIZE)
                throw std::runtime_error("Chunk size in live mode exceeds 1456 bytes; this is not supported");

            par["payloadsize"] = Sprint(transmit_chunk_size);
        }
    }

    // Assign the others here.
    m_options = par;
    m_options["mode"] = m_mode;
}

void SrtCommon::PrepareListener(string host, int port, int backlog)
{
    m_bindsock = srt_create_socket();
    if ( m_bindsock == SRT_ERROR )
        Error(UDT::getlasterror(), "srt_socket");

    int stat = ConfigurePre(m_bindsock);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePre");

    if ( !m_blocking_mode )
    {
        srt_conn_epoll = AddPoller(m_bindsock, SRT_EPOLL_OUT);
    }

    sockaddr_in sa = CreateAddrInet(host, port);
    sockaddr* psa = (sockaddr*)&sa;
    if ( transmit_verbose )
    {
        cout << "Binding a server on " << host << ":" << port << " ...";
        cout.flush();
    }
    stat = srt_bind(m_bindsock, psa, sizeof sa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_bindsock);
        Error(UDT::getlasterror(), "srt_bind");
    }

    if ( transmit_verbose )
    {
        cout << " listen... ";
        cout.flush();
    }
    stat = srt_listen(m_bindsock, backlog);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_bindsock);
        Error(UDT::getlasterror(), "srt_listen");
    }

    if ( transmit_verbose )
    {
        cout << " accept... ";
        cout.flush();
    }
    ::transmit_throw_on_interrupt = true;

    if ( !m_blocking_mode )
    {
        if ( transmit_verbose )
            cout << "[ASYNC] " << flush;

        int len = 2;
        SRTSOCKET ready[2];
        if ( srt_epoll_wait(srt_conn_epoll, 0, 0, ready, &len, -1, 0, 0, 0, 0) == -1 )
            Error(UDT::getlasterror(), "srt_epoll_wait");

        if ( transmit_verbose )
        {
            cout << "[EPOLL: " << len << " sockets] " << flush;
        }
    }
}

void SrtCommon::StealFrom(SrtCommon& src)
{
    // This is used when SrtCommon class designates a listener
    // object that is doing Accept in appropriate direction class.
    // The new object should get the accepted socket.
    m_output_direction = src.m_output_direction;
    m_blocking_mode = src.m_blocking_mode;
    m_timeout = src.m_timeout;
    m_tsbpdmode = src.m_tsbpdmode;
    m_options = src.m_options;
    m_bindsock = SRT_INVALID_SOCK; // no listener
    m_sock = src.m_sock;
    src.m_sock = SRT_INVALID_SOCK; // STEALING
}

void SrtCommon::AcceptNewClient()
{
    sockaddr_in scl;
    int sclen = sizeof scl;
    m_sock = srt_accept(m_bindsock, (sockaddr*)&scl, &sclen);
    if ( m_sock == SRT_INVALID_SOCK )
    {
        srt_close(m_bindsock);
        Error(UDT::getlasterror(), "srt_accept");
    }

    if ( transmit_verbose )
        cout << " connected.\n";
    ::transmit_throw_on_interrupt = false;

    // ConfigurePre is done on bindsock, so any possible Pre flags
    // are DERIVED by sock. ConfigurePost is done exclusively on sock.
    int stat = ConfigurePost(m_sock);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePost");
}

void SrtCommon::Init(string host, int port, string path, map<string,string> par, bool dir_output)
{
    m_output_direction = dir_output;
    InitParameters(host, path, par);

    if ( transmit_verbose )
        cout << "Opening SRT " << (dir_output ? "target" : "source") << " " << m_mode
            << "(" << (m_blocking_mode ? "" : "non-") << "blocking)"
            << " on " << host << ":" << port << endl;

    if ( m_mode == "caller" )
    {
        if (m_group_nodes.empty())
        {
            OpenClient(host, port);
        }
        else
        {
            OpenGroupClient(); // Source data are in the fields already.
        }
    }
    else if ( m_mode == "listener" )
        OpenServer(m_adapter, port);
    else if ( m_mode == "rendezvous" )
        OpenRendezvous(m_adapter, host, port);
    else
    {
        throw std::invalid_argument("Invalid 'mode'. Use 'client' or 'server'");
    }
}

int SrtCommon::AddPoller(SRTSOCKET socket, int modes)
{
    int pollid = srt_epoll_create();
    if ( pollid == -1 )
        throw std::runtime_error("Can't create epoll in nonblocking mode");
    srt_epoll_add_usock(pollid, socket, &modes);
    return pollid;
}

int SrtCommon::ConfigurePost(SRTSOCKET sock)
{
    bool yes = m_blocking_mode;
    int result = 0;
    if ( m_output_direction )
    {
        result = srt_setsockopt(sock, 0, SRTO_SNDSYN, &yes, sizeof yes);
        if ( result == -1 )
            return result;

        if ( m_timeout )
            return srt_setsockopt(sock, 0, SRTO_SNDTIMEO, &m_timeout, sizeof m_timeout);
    }
    else
    {
        result = srt_setsockopt(sock, 0, SRTO_RCVSYN, &yes, sizeof yes);
        if ( result == -1 )
            return result;

        if ( m_timeout )
            return srt_setsockopt(sock, 0, SRTO_RCVTIMEO, &m_timeout, sizeof m_timeout);
    }

    SrtConfigurePost(sock, m_options);

    for (auto o: srt_options)
    {
        if ( o.binding == SocketOption::POST && m_options.count(o.name) )
        {
            string value = m_options.at(o.name);
            bool ok = o.apply<SocketOption::SRT>(sock, value);
            if ( transmit_verbose )
            {
                if ( !ok )
                    cout << "WARNING: failed to set '" << o.name << "' (post, " << (m_output_direction? "target":"source") << ") to " << value << endl;
                else
                    cout << "NOTE: SRT/post::" << o.name << "=" << value << endl;
            }
        }
    }

    return 0;
}

int SrtCommon::ConfigurePre(SRTSOCKET sock)
{
    int result = 0;

    int no = 0;
    if ( !m_tsbpdmode )
    {
        result = srt_setsockopt(sock, 0, SRTO_TSBPDMODE, &no, sizeof no);
        if ( result == -1 )
            return result;
    }

    // Let's pretend async mode is set this way.
    // This is for asynchronous connect.
    int maybe = m_blocking_mode;
    result = srt_setsockopt(sock, 0, SRTO_RCVSYN, &maybe, sizeof maybe);
    if ( result == -1 )
        return result;

    //if ( m_timeout )
    //    result = srt_setsockopt(sock, 0, SRTO_RCVTIMEO, &m_timeout, sizeof m_timeout);
    //if ( result == -1 )
    //    return result;

    //if ( transmit_verbose )
    //{
    //    cout << "PRE: blocking mode set: " << yes << " timeout " << m_timeout << endl;
    //}

    // host is only checked for emptiness and depending on that the connection mode is selected.
    // Here we are not exactly interested with that information.
    vector<string> failures;

    // NOTE: here host = "", so the 'connmode' will be returned as LISTENER always,
    // but it doesn't matter here. We don't use 'connmode' for anything else than
    // checking for failures.
    SocketOption::Mode conmode = SrtConfigurePre(sock, "",  m_options, &failures);

    if ( conmode == SocketOption::FAILURE )
    {
        if (transmit_verbose )
        {
            cout << "WARNING: failed to set options: ";
            copy(failures.begin(), failures.end(), ostream_iterator<string>(cout, ", "));
            cout << endl;
        }

        return SRT_ERROR;
    }

    return 0;
}

void SrtCommon::SetupAdapter(const string& host, int port)
{
    sockaddr_in localsa = CreateAddrInet(host, port);
    sockaddr* psa = (sockaddr*)&localsa;
    int stat = srt_bind(m_sock, psa, sizeof localsa);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "srt_bind");
}

void SrtCommon::OpenClient(string host, int port)
{
    PrepareClient();

    if ( m_outgoing_port )
    {
        SetupAdapter("", m_outgoing_port);
    }

    ConnectClient(host, port);
}

void SrtCommon::PrepareClient()
{
    m_sock = srt_create_socket();
    if ( m_sock == SRT_ERROR )
        Error(UDT::getlasterror(), "srt_socket");

    int stat = ConfigurePre(m_sock);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePre");

    if ( !m_blocking_mode )
    {
        srt_conn_epoll = AddPoller(m_sock, SRT_EPOLL_OUT);
    }

}

void SrtCommon::OpenGroupClient()
{
    SRT_GROUP_TYPE type = SRT_GTYPE_UNDEFINED;

    // Resolve group type.
    if (m_group_type == "redundancy")
        type = SRT_GTYPE_REDUNDANT;
    // else if blah blah blah...
    else
    {
        Error("With //group, type='" + m_group_type + "' undefined");
    }

    m_sock = srt_create_group(type);

    int stat = ConfigurePre(m_sock);

    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePre");

    if ( !m_blocking_mode )
    {
        // Note: here the GROUP is added to the poller.
        srt_conn_epoll = AddPoller(m_sock, SRT_EPOLL_OUT);
    }

    // ConnectClient can't be used here, the code must
    // be more-less repeated. In this case the situation
    // that not all connections can be established is tolerated,
    // the only case of error is when none of the connections
    // can be established.

    bool any_node = false;

    if (transmit_verbose)
    {
        cout << "REDUNDANT connections with " << m_group_nodes.size() << " nodes:\n";
    }

    int i = 1;
    for (Connection& c: m_group_nodes)
    {
        sockaddr_in sa = CreateAddrInet(c.host, c.port);
        sockaddr* psa = (sockaddr*)&sa;
        if ( transmit_verbose )
        {
            cout << "[" << i << "] Connecting to node " << c.host << ":" << c.port << " ... ";
            cout.flush();
        }
        ++i;

        int insock = srt_connect(m_sock, psa, sizeof sa);
        if (insock == SRT_ERROR)
        {
            // Whatever. Skip the node.
            if (transmit_verbose)
            {
                cout << "FAILED: \n";
            }
        }
        else
        {
            int stat = ConfigurePost(insock);
            if (stat == -1)
            {
                // This kind of error must reject the whole operation.
                // Usually you'll get this error on the first socket,
                // and doing this on the others would result in the same.
                Error(UDT::getlasterror(), "ConfigurePost");
            }

            // Have socket, store it into the group socket array.
            c.socket = insock;
            c.status = 0;
            any_node = true;
        }
    }

    // Wait for REAL connected state if nonblocking mode, for AT LEAST one node.
    if ( !m_blocking_mode )
    {
        if ( transmit_verbose )
            cout << "[ASYNC] " << flush;

        // SPIN-WAITING version. Don't use it unless you know what you're doing.
        // SpinWaitAsync();

        // Socket readiness for connection is checked by polling on WRITE allowed sockets.
        int len = 2;
        SRTSOCKET ready[2];
        if ( srt_epoll_wait(srt_conn_epoll, 0, 0, ready, &len, -1, 0, 0, 0, 0) != -1 )
        {
            if ( transmit_verbose )
            {
                cout << "[EPOLL: " << len << " sockets] " << flush;
            }
        }
        else
        {
            Error(UDT::getlasterror(), "srt_epoll_wait");
        }
    }

    if (!any_node)
    {
        Error("REDUNDANCY: all redundant connections failed");
    }

    // Prepare group data for monitoring the group status.
    m_group_data.resize(m_group_nodes.size());
}

/*
 This may be used sometimes for testing, but it's nonportable.
void SrtCommon::SpinWaitAsync()
{
    static string udt_status_names [] = {
        "INIT" , "OPENED", "LISTENING", "CONNECTING", "CONNECTED", "BROKEN", "CLOSING", "CLOSED", "NONEXIST"
    };

    for (;;)
    {
        SRT_SOCKSTATUS state = srt_getsockstate(m_sock);
        if ( int(state) < SRTS_CONNECTED )
        {
            if ( transmit_verbose )
                cout << state << flush;
            usleep(250000);
            continue;
        }
        else if ( int(state) > SRTS_CONNECTED )
        {
            Error(UDT::getlasterror(), "UDT::connect status=" + udt_status_names[state]);
        }

        return;
    }
}
*/

void SrtCommon::ConnectClient(string host, int port)
{
    sockaddr_in sa = CreateAddrInet(host, port);
    sockaddr* psa = (sockaddr*)&sa;
    if ( transmit_verbose )
    {
        cout << "Connecting to " << host << ":" << port << " ... ";
        cout.flush();
    }
    int stat = srt_connect(m_sock, psa, sizeof sa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_sock);
        Error(UDT::getlasterror(), "srt_connect");
    }

    // Wait for REAL connected state if nonblocking mode
    if ( !m_blocking_mode )
    {
        if ( transmit_verbose )
            cout << "[ASYNC] " << flush;

        // SPIN-WAITING version. Don't use it unless you know what you're doing.
        // SpinWaitAsync();

        // Socket readiness for connection is checked by polling on WRITE allowed sockets.
        int len = 2;
        SRTSOCKET ready[2];
        if ( srt_epoll_wait(srt_conn_epoll, 0, 0, ready, &len, -1, 0, 0, 0, 0) != -1 )
        {
            if ( transmit_verbose )
            {
                cout << "[EPOLL: " << len << " sockets] " << flush;
            }
        }
        else
        {
            Error(UDT::getlasterror(), "srt_epoll_wait");
        }
    }

    if ( transmit_verbose )
        cout << " connected.\n";
    stat = ConfigurePost(m_sock);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePost");
}

void SrtCommon::Error(UDT::ERRORINFO& udtError, string src)
{
    int udtResult = udtError.getErrorCode();
    string message = udtError.getErrorMessage();
    if ( transmit_verbose )
        cout << "FAILURE\n" << src << ": [" << udtResult << "] " << message << endl;
    else
        cerr << "\nERROR #" << udtResult << ": " << message << endl;

    udtError.clear();
    throw std::runtime_error("error: " + src + ": " + message);
}

void SrtCommon::Error(string msg)
{
    cerr << "\nERROR (app): " << msg << endl;
    throw std::runtime_error(msg);
}

void SrtCommon::OpenRendezvous(string adapter, string host, int port)
{
    m_sock = srt_create_socket();
    if ( m_sock == SRT_ERROR )
        Error(UDT::getlasterror(), "srt_socket");

    bool yes = true;
    srt_setsockopt(m_sock, 0, SRTO_RENDEZVOUS, &yes, sizeof yes);

    int stat = ConfigurePre(m_sock);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePre");

    if ( !m_blocking_mode )
    {
        srt_conn_epoll = AddPoller(m_sock, SRT_EPOLL_OUT);
    }

    sockaddr_in localsa = CreateAddrInet(adapter, port);
    sockaddr* plsa = (sockaddr*)&localsa;
    if ( transmit_verbose )
    {
        cout << "Binding a server on " << adapter << ":" << port << " ...";
        cout.flush();
    }
    stat = srt_bind(m_sock, plsa, sizeof localsa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_sock);
        Error(UDT::getlasterror(), "srt_bind");
    }

    sockaddr_in sa = CreateAddrInet(host, port);
    sockaddr* psa = (sockaddr*)&sa;
    if ( transmit_verbose )
    {
        cout << "Connecting to " << host << ":" << port << " ... ";
        cout.flush();
    }
    stat = srt_connect(m_sock, psa, sizeof sa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_sock);
        Error(UDT::getlasterror(), "srt_connect");
    }

    // Wait for REAL connected state if nonblocking mode
    if ( !m_blocking_mode )
    {
        if ( transmit_verbose )
            cout << "[ASYNC] " << flush;

        // SPIN-WAITING version. Don't use it unless you know what you're doing.
        // SpinWaitAsync();

        // Socket readiness for connection is checked by polling on WRITE allowed sockets.
        int len = 2;
        SRTSOCKET ready[2];
        if ( srt_epoll_wait(srt_conn_epoll, 0, 0, ready, &len, -1, 0, 0, 0, 0) != -1 )
        {
            if ( transmit_verbose )
            {
                cout << "[EPOLL: " << len << " sockets] " << flush;
            }
        }
        else
        {
            Error(UDT::getlasterror(), "srt_epoll_wait");
        }
    }

    if ( transmit_verbose )
        cout << " connected.\n";

    stat = ConfigurePost(m_sock);
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "ConfigurePost");
}

void SrtCommon::Close()
{
    if ( transmit_verbose )
        cout << "SrtCommon: DESTROYING CONNECTION, closing sockets (rt%" << m_sock << " ls%" << m_bindsock << ")...\n";

    bool yes = true;
    if ( m_sock != UDT::INVALID_SOCK )
    {
        srt_setsockflag(m_sock, SRTO_SNDSYN, &yes, sizeof yes);
        srt_close(m_sock);
    }

    if ( m_bindsock != UDT::INVALID_SOCK )
    {
        // Set sndsynchro to the socket to synch-close it.
        srt_setsockflag(m_bindsock, SRTO_SNDSYN, &yes, sizeof yes);
        srt_close(m_bindsock);
    }
    if ( transmit_verbose )
        cout << "SrtCommon: ... done.\n";
}

SrtCommon::~SrtCommon()
{
    Close();
}


void SrtCommon::UpdateGroupStatus(const SRT_SOCKGROUPDATA* grpdata, size_t grpdata_size)
{
    if (!grpdata)
    {
        // This happens when you passed too small array. Treat this as error and stop.
        cerr << "ERROR: redundancy group update reports " << grpdata_size
            << " existing sockets, but app registerred only " << m_group_nodes.size() << endl;
        Error("Too many unpredicted sockets in the group");
    }

    // Note: sockets are not necessarily in the same order. Find
    // the socket by id.
    for (size_t i = 0; i < grpdata_size; ++i)
    {
        SRTSOCKET id = grpdata[i].id;

        SRT_SOCKSTATUS status = grpdata[i].status;
        int result = grpdata[i].result;

        if (result != -1 && status == SRTS_CONNECTED)
        {
            // Everything's ok. Don't do anything.
            continue;
        }

        auto pgi = find_if(m_group_nodes.begin(), m_group_nodes.end(), [id](Connection& c) { return c.socket == id; });
        if (pgi == m_group_nodes.end())
        {
            // A new socket appeared out of the blue. Internal error?
            Error("Unregisterred socket ID appeared in the status. INTERNAL ERROR.");
        }

        sockaddr_in sa = CreateAddrInet(pgi->host, pgi->port);
        sockaddr* psa = (sockaddr*)&sa;
        if ( transmit_verbose )
        {
            cout << "[" << i << "] RECONNECTING to node " << pgi->host << ":" << pgi->port << " ... ";
            cout.flush();
        }
        ++i;

        int insock = srt_connect(m_sock, psa, sizeof sa);
        if (insock == SRT_ERROR)
        {
            // Whatever. Skip the node.
            if (transmit_verbose)
            {
                cout << "FAILED: \n";
            }
        }
        else
        {
            ConfigurePost(insock);
            // Ignore error this time. It's unlikely that an error
            // will pop up at the time of reconnecting.

            // Have socket, store it into the group socket array.
            pgi->socket = insock;
            pgi->status = 0;
        }
    }
}

SrtSource::SrtSource(string host, int port, std::string path, const map<string,string>& par)
{
    Init(host, port, path, par, false);

    if ( !m_blocking_mode )
    {
        srt_epoll = AddPoller(m_sock, SRT_EPOLL_IN);
    }

    ostringstream os;
    os << host << ":" << port;
    hostport_copy = os.str();
}

bytevector SrtSource::Read(size_t chunk)
{
    static size_t counter = 1;

    SRT_MSGCTRL mctrl = srt_msgctrl_default;
    bool have_group = !m_group_nodes.empty();
    if (have_group)
    {
        mctrl.grpdata = m_group_data.data();
        mctrl.grpdata_size = m_group_data.size();
    }

    bytevector data(chunk);
    bool ready = true;
    int stat;
    do
    {
        ::transmit_throw_on_interrupt = true;
        stat = srt_recvmsg2(m_sock, data.data(), chunk, &mctrl);
        ::transmit_throw_on_interrupt = false;
        if ( stat == SRT_ERROR )
        {
            if ( !m_blocking_mode )
            {
                // EAGAIN for SRT READING
                if ( srt_getlasterror(NULL) == SRT_EASYNCRCV )
                {
                    Verb() << "AGAIN: - waiting for data by epoll...";
                    // Poll on this descriptor until reading is available, indefinitely.
                    int len = 2;
                    SRTSOCKET sready[2];
                    if ( srt_epoll_wait(srt_epoll, sready, &len, 0, 0, -1, 0, 0, 0, 0) != -1 )
                    {
                        if ( transmit_verbose )
                        {
                            cout << "... epoll reported ready " << len << " sockets\n";
                        }
                        continue;
                    }
                    // If was -1, then passthru.
                }
            }
            Error(UDT::getlasterror(), "recvmsg");
        }

        if ( stat == 0 )
        {
            throw ReadEOF(hostport_copy);
        }
    }
    while (!ready);

    chunk = size_t(stat);
    if ( chunk < data.size() )
        data.resize(chunk);

    if (have_group)
    {
        UpdateGroupStatus(mctrl.grpdata, mctrl.grpdata_size);
    }

    CBytePerfMon perf;
    srt_bstats(m_sock, &perf, true);
    if ( transmit_bw_report && int(counter % transmit_bw_report) == transmit_bw_report - 1 )
    {
        cout << "+++/+++SRT BANDWIDTH: " << perf.mbpsBandwidth << endl;
    }

    if ( transmit_stats_report && counter % transmit_stats_report == transmit_stats_report - 1)
    {
        PrintSrtStats(m_sock, perf);
    }

    ++counter;

    return data;
}

int SrtTarget::ConfigurePre(SRTSOCKET sock)
{
    int result = SrtCommon::ConfigurePre(sock);
    if ( result == -1 )
        return result;

    int yes = 1;
    // This is for the HSv4 compatibility, if both parties are HSv5
    // (min. version 1.2.1), then this setting simply does nothing.
    // In HSv4 this setting is obligatory otherwise the SRT handshake
    // extension will not be done at all.
    result = srt_setsockopt(sock, 0, SRTO_SENDER, &yes, sizeof yes);
    if ( result == -1 )
        return result;

    return 0;
}

void SrtTarget::Write(const bytevector& data) 
{
    ::transmit_throw_on_interrupt = true;

    // Check first if it's ready to write.
    // If not, wait indefinitely.
    if ( !m_blocking_mode )
    {
        int ready[2];
        int len = 2;
        if ( srt_epoll_wait(srt_epoll, 0, 0, ready, &len, -1, 0, 0, 0, 0) == SRT_ERROR )
            Error(UDT::getlasterror(), "srt_epoll_wait");
    }

    SRT_MSGCTRL mctrl = srt_msgctrl_default;
    bool have_group = !m_group_nodes.empty();
    if (have_group)
    {
        mctrl.grpdata = m_group_data.data();
        mctrl.grpdata_size = m_group_data.size();
    }

    int stat = srt_sendmsg2(m_sock, data.data(), data.size(), &mctrl);

    // For a socket group, the error is reported only
    // if ALL links from the group have failed to perform
    // the operation. If only one did, the result will be
    // visible in the status array.
    if ( stat == SRT_ERROR )
        Error(UDT::getlasterror(), "srt_sendmsg");
    ::transmit_throw_on_interrupt = false;

    if (have_group)
    {
        UpdateGroupStatus(mctrl.grpdata, mctrl.grpdata_size);
    }
}

SrtModel::SrtModel(string host, int port, map<string,string> par)
{
    InitParameters(host, "", par);
    if (m_mode == "caller")
        is_caller = true;
    else if (m_mode != "listener")
        throw std::invalid_argument("Only caller and listener modes supported");

    m_host = host;
    m_port = port;
}


void SrtModel::Establish(ref_t<std::string> name)
{
    // This does connect or accept.
    // When this returned true, the caller should create
    // a new SrtSource or SrtTaget then call StealFrom(*this) on it.

    // If this is a connector and the peer doesn't have a corresponding
    // medium, it should send back a single byte with value 0. This means
    // that agent should stop connecting.

    if (is_caller)
    {
        // Establish a connection

        PrepareClient();

        if (name.get() != "")
        {
            Verb() << "Connect with requesting stream [" << name.get() << "]";
            UDT::setstreamid(m_sock, *name);
        }
        else
        {
            Verb() << "NO STREAM ID for SRT connection";
        }

        if (m_outgoing_port)
        {
            Verb() << "Setting outgoing port: " << m_outgoing_port;
            SetupAdapter("", m_outgoing_port);
        }

        ConnectClient(m_host, m_port);

        if (m_outgoing_port == 0)
        {
            // Must rely on a randomly selected one. Extract the port
            // so that it will be reused next time.
            sockaddr_any s(AF_INET);
            int namelen = s.size();
            if ( srt_getsockname(Socket(), &s, &namelen) == SRT_ERROR )
            {
                Error(UDT::getlasterror(), "srt_getsockname");
            }

            m_outgoing_port = s.hport();
            Verb() << "Extracted outgoing port: " << m_outgoing_port;
        }
    }
    else
    {
        // Listener - get a socket by accepting.
        // Check if the listener is already created first
        if (Listener() == SRT_INVALID_SOCK)
        {
            Verb() << "Setting up listener: port=" << m_port << " backlog=5";
            PrepareListener(m_adapter, m_port, 5);
        }

        Verb() << "Accepting a client...";
        AcceptNewClient();
        // This rewrites m_sock with a new SRT socket ("accepted" socket)
        *name = UDT::getstreamid(m_sock);
        Verb() << "... GOT CLIENT for stream [" << name.get() << "]";
    }
}



template <class Iface> struct Srt;
template <> struct Srt<Source> { typedef SrtSource type; };
template <> struct Srt<Target> { typedef SrtTarget type; };

template <class Iface>
Iface* CreateSrt(const string& host, int port,
        const string& path, const map<string,string>& par)
{
    return new typename Srt<Iface>::type (host, port, path, par);
}

class ConsoleSource: public Source
{
public:

    ConsoleSource()
    {
    }

    bytevector Read(size_t chunk) override
    {
        bytevector data(chunk);
		bool st = cin.read(data.data(), chunk).good();
        chunk = cin.gcount();
        if ( chunk == 0 && !st )
            return bytevector();

        if ( chunk < data.size() )
            data.resize(chunk);
        if ( data.empty() )
            throw ReadEOF("CONSOLE device");

        return data;
    }

    bool IsOpen() override { return cin.good(); }
    bool End() override { return cin.eof(); }
};

class ConsoleTarget: public Target
{
public:

    ConsoleTarget()
    {
    }

    void Write(const bytevector& data) override
    {
        cout.write(data.data(), data.size());
    }

    bool IsOpen() override { return cout.good(); }
    bool Broken() override { return cout.eof(); }
};

template <class Iface> struct Console;
template <> struct Console<Source> { typedef ConsoleSource type; };
template <> struct Console<Target> { typedef ConsoleTarget type; };

template <class Iface>
Iface* CreateConsole() { return new typename Console<Iface>::type (); }


// More options can be added in future.
SocketOption udp_options [] {
    { "ipttl", IPPROTO_IP, IP_TTL, SocketOption::PRE, SocketOption::INT, nullptr },
    { "iptos", IPPROTO_IP, IP_TOS, SocketOption::PRE, SocketOption::INT, nullptr },
};

class UdpCommon
{
protected:
    int m_sock = -1;
    sockaddr_in sadr;
    string adapter;
    map<string, string> m_options;

    void Setup(string host, int port, map<string,string> attr)
    {
        m_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (m_sock == -1)
            Error(SysError(), "UdpCommon::Setup: socket");

        int yes = 1;
        ::setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);

        sadr = CreateAddrInet(host, port);

        if ( attr.count("multicast") )
        {
            adapter = attr.count("adapter") ? attr.at("adapter") : string();
            sockaddr_in maddr;
            if ( adapter == "" )
            {
                Verb() << "Multicast: home address: INADDR_ANY:" << port;
                maddr.sin_family = AF_INET;
                maddr.sin_addr.s_addr = htonl(INADDR_ANY);
                maddr.sin_port = htons(port); // necessary for temporary use
            }
            else
            {
                Verb() << "Multicast: home address: " << adapter << ":" << port;
                maddr = CreateAddrInet(adapter, port);
            }

            ip_mreq mreq;
            mreq.imr_multiaddr.s_addr = sadr.sin_addr.s_addr;
            mreq.imr_interface.s_addr = maddr.sin_addr.s_addr;
#ifdef WIN32
            const char* mreq_arg = (const char*)&mreq;
            const auto status_error = SOCKET_ERROR;
#else
            const void* mreq_arg = &mreq;
            const auto status_error = -1;
#endif

#if defined(WIN32) || defined(__CYGWIN__)
            // On Windows it somehow doesn't work when bind()
            // is called with multicast address. Write the address
            // that designates the network device here.
            sadr = maddr;
            Verb() << "Multicast(Windows): will bind to home address";
#else
            Verb() << "Multicast(POSIX): will bind to IGMP address: " << host;
#endif
            int res = setsockopt(m_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq_arg, sizeof(mreq));

            if ( res == status_error )
            {
                throw runtime_error("adding to multicast membership failed");
            }
            attr.erase("multicast");
            attr.erase("adapter");
        }

        m_options = attr;

        for (auto o: udp_options)
        {
            // Ignore "binding" - for UDP there are no post options.
            if ( m_options.count(o.name) )
            {
                string value = m_options.at(o.name);
                bool ok = o.apply<SocketOption::SYSTEM>(m_sock, value);
                if ( transmit_verbose && !ok )
                    cout << "WARNING: failed to set '" << o.name << "' to " << value << endl;
            }
        }
    }

    void Error(int err, string src)
    {
        char buf[512];
        string message = SysStrError(err, buf, 512u);

        if ( transmit_verbose )
            cout << "FAILURE\n" << src << ": [" << err << "] " << message << endl;
        else
            cerr << "\nERROR #" << err << ": " << message << endl;

        throw std::runtime_error("error: " + src + ": " + message);
    }

    ~UdpCommon()
    {
#ifdef WIN32
        if (m_sock != -1)
        {
           shutdown(m_sock, SD_BOTH);
           closesocket(m_sock);
           m_sock = -1;
        }
#else
        close(m_sock);
#endif
    }
};


class UdpSource: public Source, public UdpCommon
{
    bool eof = true;
public:

    UdpSource(string host, int port, const map<string,string>& attr)
    {
        Setup(host, port, attr);
        int stat = ::bind(m_sock, (sockaddr*)&sadr, sizeof sadr);
        if ( stat == -1 )
            Error(SysError(), "Binding address for UDP");
        eof = false;
    }

    bytevector Read(size_t chunk) override
    {
        bytevector data(chunk);
        sockaddr_in sa;
        socklen_t si = sizeof(sockaddr_in);
        int stat = recvfrom(m_sock, data.data(), chunk, 0, (sockaddr*)&sa, &si);
        if ( stat == -1 )
            Error(SysError(), "UDP Read/recvfrom");

        if ( stat < 1 )
        {
            eof = true;
            return bytevector();
        }

        chunk = size_t(stat);
        if ( chunk < data.size() )
            data.resize(chunk);

        return data;
    }

    bool IsOpen() override { return m_sock != -1; }
    bool End() override { return eof; }
};

class UdpTarget: public Target, public UdpCommon
{
public:
    UdpTarget(string host, int port, const map<string,string>& attr )
    {
        Setup(host, port, attr);
    }

    void Write(const bytevector& data) override
    {
        int stat = sendto(m_sock, data.data(), data.size(), 0, (sockaddr*)&sadr, sizeof sadr);
        if ( stat == -1 )
            Error(SysError(), "UDP Write/sendto");
    }

    bool IsOpen() override { return m_sock != -1; }
    bool Broken() override { return false; }
};

template <class Iface> struct Udp;
template <> struct Udp<Source> { typedef UdpSource type; };
template <> struct Udp<Target> { typedef UdpTarget type; };

template <class Iface>
Iface* CreateUdp(const string& host, int port, const map<string,string>& par) { return new typename Udp<Iface>::type (host, port, par); }

template<class Base>
inline bool IsOutput() { return false; }

template<>
inline bool IsOutput<Target>() { return true; }

template <class Base>
extern unique_ptr<Base> CreateMedium(const string& uri)
{
    unique_ptr<Base> ptr;

    UriParser u(uri);

    int iport = 0;
    switch ( u.type() )
    {
    default: ; // do nothing, return nullptr
    case UriParser::FILE:
        if ( u.host() == "con" || u.host() == "console" )
        {
            if ( IsOutput<Base>() && (
                        (transmit_verbose && transmit_cverb == &cout)
                        || transmit_bw_report) )
            {
                cerr << "ERROR: file://con with -v or -r would result in mixing the data and text info.\n";
                cerr << "ERROR: HINT: you can stream through a FIFO (named pipe)\n";
                throw invalid_argument("incorrect parameter combination");
            }
            ptr.reset( CreateConsole<Base>() );
        }
        else
            ptr.reset( CreateFile<Base>(u.path()));
        break;


    case UriParser::SRT:
        ptr.reset( CreateSrt<Base>(u.host(), u.portno(), u.path(), u.parameters()) );
        break;


    case UriParser::UDP:
        iport = atoi(u.port().c_str());
        if ( iport <= 1024 )
        {
            cerr << "Port value invalid: " << iport << " - must be >1024\n";
            throw invalid_argument("Invalid port number");
        }
        ptr.reset( CreateUdp<Base>(u.host(), iport, u.parameters()) );
        break;

    }

    ptr->uri = move(u);
    return ptr;
}


std::unique_ptr<Source> Source::Create(const std::string& url)
{
    return CreateMedium<Source>(url);
}

std::unique_ptr<Target> Target::Create(const std::string& url)
{
    return CreateMedium<Target>(url);
}
