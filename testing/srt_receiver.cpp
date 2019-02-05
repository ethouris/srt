#include <iostream>
#include <iterator>
#include "apputil.hpp"  // CreateAddrInet
#include "uriparser.hpp"  // UriParser
#include "socketoptions.hpp"
#include "logsupport.hpp"
#include "verbose.hpp"
#include "srt_receiver.hpp"


using namespace std;



SrtReceiver::SrtReceiver(std::string host, int port, std::map<string, string> par)
    : m_host(host)
    , m_port(port)
    , m_options(par)
{
    Verbose::on = true;
    srt_startup();

    m_epoll_accept  = srt_epoll_create();
    if (m_epoll_accept == -1)
        throw std::runtime_error("Can't create epoll in nonblocking mode");
    m_epoll_receive = srt_epoll_create();
    if (m_epoll_receive == -1)
        throw std::runtime_error("Can't create epoll in nonblocking mode");
}


SrtReceiver::~SrtReceiver()
{
    m_stop_accept = true;
    m_accepting_thread.join();
}


void SrtReceiver::AcceptingThread()
{
    int rnum = 2;
    SRTSOCKET read_fds[2] = {};

    while (!m_stop_accept)
    {
        const int epoll_res 
            = srt_epoll_wait(m_epoll_accept, read_fds, &rnum, 0, 0, 3000,
                                                    0,     0, 0, 0);

        if (epoll_res > 0)
        {
            Verb() << "AcceptingThread: epoll res " << epoll_res << " rnum: " << rnum;
            const SRTSOCKET sock = AcceptNewClient();
            if (sock != SRT_INVALID_SOCK)
            {
                m_accepted_sockets.push_back(sock);
                const int events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
                srt_epoll_add_usock(m_epoll_receive, sock, &events);
            }
        }
    }
}


SRTSOCKET SrtReceiver::AcceptNewClient()
{
    sockaddr_in scl;
    int sclen = sizeof scl;

    Verb() << " accept..." << VerbNoEOL;

    const SRTSOCKET socket = srt_accept(m_bindsock, (sockaddr*)&scl, &sclen);
    if (socket == SRT_INVALID_SOCK)
    {
        Verb() << " failed: " << srt_getlasterror_str();
        return socket;
    }

    Verb() << " connected " << socket;
    ::transmit_throw_on_interrupt = false;

    // ConfigurePre is done on bindsock, so any possible Pre flags
    // are DERIVED by sock. ConfigurePost is done exclusively on sock.
    const int stat = ConfigureAcceptedSocket(socket);
    if (stat == SRT_ERROR)
        Verb() << "ConfigureAcceptedSocket failed: " << srt_getlasterror_str();

    return socket;
}



int SrtReceiver::ConfigureAcceptedSocket(SRTSOCKET sock)
{
    bool no = false;
    const int result = srt_setsockopt(sock, 0, SRTO_RCVSYN, &no, sizeof no);
    if (result == -1)
        return result;

    //if (m_timeout)
    //    return srt_setsockopt(sock, 0, SRTO_RCVTIMEO, &m_timeout, sizeof m_timeout);

    SrtConfigurePost(sock, m_options);

    return 0;
}


int SrtReceiver::ConfigurePre(SRTSOCKET sock)
{
    const int no = 0;

    int result = 0;
    result = srt_setsockopt(sock, 0, SRTO_TSBPDMODE, &no, sizeof no);
    if (result == -1)
        return result;

    // Non-blocking receiving mode
    result = srt_setsockopt(sock, 0, SRTO_RCVSYN, &no, sizeof no);
    if (result == -1)
        return result;

    // host is only checked for emptiness and depending on that the connection mode is selected.
    // Here we are not exactly interested with that information.
    vector<string> failures;

    // NOTE: here host = "", so the 'connmode' will be returned as LISTENER always,
    // but it doesn't matter here. We don't use 'connmode' for anything else than
    // checking for failures.
    SocketOption::Mode conmode = SrtConfigurePre(sock, "", m_options, &failures);

    if (conmode == SocketOption::FAILURE)
    {
        if (Verbose::on)
        {
            Verb() << "WARNING: failed to set options: ";
            copy(failures.begin(), failures.end(), ostream_iterator<string>(*Verbose::cverb, ", "));
            Verb();
        }

        return SRT_ERROR;
    }

    return 0;
}


int SrtReceiver::Listen(int max_conn)
{
    m_bindsock = srt_create_socket();

    if (m_bindsock == SRT_INVALID_SOCK)
        return SRT_ERROR;

    int stat = ConfigurePre(m_bindsock);
    if (stat == SRT_ERROR)
        return SRT_ERROR;

    const int modes = SRT_EPOLL_IN;
    srt_epoll_add_usock(m_epoll_accept, m_bindsock, &modes);

    sockaddr_in sa = CreateAddrInet(m_host, m_port);
    sockaddr* psa = (sockaddr*)&sa;
    Verb() << "Binding a server on " << m_host << ":" << m_port << VerbNoEOL;
    stat = srt_bind(m_bindsock, psa, sizeof sa);
    if (stat == SRT_ERROR)
    {
        srt_close(m_bindsock);
        return SRT_ERROR;
    }
    Verb() << " listening";

    stat = srt_listen(m_bindsock, max_conn);
    if (stat == SRT_ERROR)
    {
        srt_close(m_bindsock);
        return SRT_ERROR;
    }

    m_epoll_read_fds .assign(max_conn, SRT_INVALID_SOCK);
    m_epoll_write_fds.assign(max_conn, SRT_INVALID_SOCK);

    m_accepting_thread = thread(&SrtReceiver::AcceptingThread, this);

    return 0;
}


int SrtReceiver::Receive(char * buffer, size_t buffer_len)
{
    const int wait_ms = 3000;
    while (!m_stop_accept)
    {
        fill(m_epoll_read_fds.begin(),  m_epoll_read_fds.end(),  SRT_INVALID_SOCK);
        fill(m_epoll_write_fds.begin(), m_epoll_write_fds.end(), SRT_INVALID_SOCK);
        int rnum = (int) m_epoll_read_fds .size();
        int wnum = (int) m_epoll_write_fds.size();

        const int epoll_res = srt_epoll_wait(m_epoll_receive,
            m_epoll_read_fds.data(),  &rnum,
            m_epoll_write_fds.data(), &wnum,
            wait_ms, 0, 0, 0, 0);

        if (epoll_res > 0)
        {
            {
                // Verbose info:
                Verb() << "Received epoll_res " << epoll_res;
                Verb() << "   to read  " << rnum << ": " << VerbNoEOL;
                copy(m_epoll_read_fds.begin(), next(m_epoll_read_fds.begin(), rnum),
                    ostream_iterator<int>(*Verbose::cverb, ", "));
                Verb();
                Verb() << "   to write " << wnum << ": " << VerbNoEOL;
                copy(m_epoll_write_fds.begin(), next(m_epoll_write_fds.begin(), wnum),
                    ostream_iterator<int>(*Verbose::cverb, ", "));
                Verb();
            }

            // First we need to check errors on the sockets
            if (wnum > 0)
            {
                for (int i = 0; i < wnum; ++i)
                {
                    const SRTSOCKET socket = m_epoll_write_fds[i];
                    auto read_sock = std::find(m_epoll_read_fds.begin(), m_epoll_read_fds.end(), socket);
                    if (read_sock != m_epoll_read_fds.end())
                        *read_sock = SRT_INVALID_SOCK;
                    else
                        Verb() << "Socket " << socket << " is not in writefds";

                    const SRT_SOCKSTATUS status = srt_getsockstate(socket);

                    switch (status)
                    {
                    case SRTS_BROKEN:
                    case SRTS_NONEXIST:
                    case SRTS_CLOSED:
                        Verb() << "Socket " << socket << " status " << status << " is closing. Remove from epoll";
                        srt_close(socket);
                        break;
                    default:
                        Verb() << "Socket " << socket << " state " << status << " (don'tknow what to do)";
                        break;
                    }
                }
            }

            const auto read_sock = std::find_if(m_epoll_read_fds.begin(), m_epoll_read_fds.end(),
                [](const SRTSOCKET &sock) { return (sock != SRT_INVALID_SOCK); });

            if (read_sock != m_epoll_read_fds.end())
            {
                const SRTSOCKET sock = *read_sock;
                int res = srt_recvmsg2(sock, buffer, buffer_len, nullptr);
                Verb() << "Received message result " << res;
                return res;
            }
        }
    }
    return 0;
}
