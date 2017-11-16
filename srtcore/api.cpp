/*****************************************************************************
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2017 Haivision Systems Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>
 * 
 * Based on UDT4 SDK version 4.11
 *****************************************************************************/

/*****************************************************************************
Copyright (c) 2001 - 2011, The Board of Trustees of the University of Illinois.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the
  above copyright notice, this list of conditions
  and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the University of Illinois
  nor the names of its contributors may be used to
  endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/*****************************************************************************
written by
   Yunhong Gu, last updated 07/09/2011
modified by
   Haivision Systems Inc.
*****************************************************************************/

#include <exception>
#include <stdexcept>
#include <typeinfo>
#include <iterator>

#include <cstring>
#include "platform_sys.h"
#include "utilities.h"
#include "netinet_any.h"
#include "api.h"
#include "core.h"
#include "logging.h"
#include "threadname.h"
#include "srt.h"

using namespace std;

extern logging::LogConfig srt_logger_config;

extern logging::Logger mglog;

void CUDTSocket::construct()
{
    m_IncludedGroup = NULL;
    m_IncludedIter = CUDTGroup::gli_NULL();
    pthread_mutex_init(&m_AcceptLock, NULL);
    pthread_cond_init(&m_AcceptCond, NULL);
    pthread_mutex_init(&m_ControlLock, NULL);
}

CUDTSocket::~CUDTSocket()
{
   pthread_mutex_destroy(&m_AcceptLock);
   pthread_cond_destroy(&m_AcceptCond);
   pthread_mutex_destroy(&m_ControlLock);
}


SRT_SOCKSTATUS CUDTSocket::getStatus()
{
    if (m_Core.m_bBroken)
        return SRTS_BROKEN;

    // Connecting timed out
    if ((m_Status == SRTS_CONNECTING) && !m_Core.m_bConnecting)
        return SRTS_BROKEN;

    return m_Status;
}


////////////////////////////////////////////////////////////////////////////////

CUDTUnited::CUDTUnited():
m_Sockets(),
m_ControlLock(),
m_IDLock(),
m_TLSError(),
m_mMultiplexer(),
m_MultiplexerLock(),
m_pCache(NULL),
m_bClosing(false),
m_GCStopLock(),
m_GCStopCond(),
m_InitLock(),
m_iInstanceCount(0),
m_bGCStatus(false),
m_GCThread(),
m_ClosedSockets()
{
   // Socket ID MUST start from a random value
   srand((unsigned int)CTimer::getTime());
   double rand1_0 = double(rand())/RAND_MAX;

   m_SocketIDGenerator = 1 + int(MAX_SOCKET_VAL * rand1_0);
   m_SocketIDGenerator_init = m_SocketIDGenerator;

   pthread_mutex_init(&m_ControlLock, NULL);
   pthread_mutex_init(&m_IDLock, NULL);
   pthread_mutex_init(&m_InitLock, NULL);

   pthread_key_create(&m_TLSError, TLSDestroy);

   m_pCache = new CCache<CInfoBlock>;
}

CUDTUnited::~CUDTUnited()
{
    // Call it if it wasn't called already.
    // This will happen at the end of main() of the application,
    // when the user didn't call srt_cleanup().
    if (m_bGCStatus)
    {
        cleanup();
    }

    pthread_mutex_destroy(&m_ControlLock);
    pthread_mutex_destroy(&m_IDLock);
    pthread_mutex_destroy(&m_InitLock);

    pthread_key_delete(m_TLSError);

    delete m_pCache;
}

std::string CUDTUnited::CONID(SRTSOCKET sock) const
{
    if ( sock == 0 )
        return "";

    std::ostringstream os;
    os << "%" << sock << ":";
    return os.str();
}

int CUDTUnited::startup()
{
   CGuard gcinit(m_InitLock);

   if (m_iInstanceCount++ > 0)
      return 0;

   // Global initialization code
   #ifdef WIN32
      WORD wVersionRequested;
      WSADATA wsaData;
      wVersionRequested = MAKEWORD(2, 2);

      if (0 != WSAStartup(wVersionRequested, &wsaData))
         throw CUDTException(MJ_SETUP, MN_NONE,  WSAGetLastError());
   #endif

   //init CTimer::EventLock

   if (m_bGCStatus)
      return true;

   m_bClosing = false;
   pthread_mutex_init(&m_GCStopLock, NULL);
   pthread_cond_init(&m_GCStopCond, NULL);

   {
       ThreadName tn("SRT:GC");
       pthread_create(&m_GCThread, NULL, garbageCollect, this);
   }

   m_bGCStatus = true;

   return 0;
}

int CUDTUnited::cleanup()
{
   CGuard gcinit(m_InitLock);

   if (--m_iInstanceCount > 0)
      return 0;

   //destroy CTimer::EventLock

   if (!m_bGCStatus)
      return 0;

   m_bClosing = true;
   pthread_cond_signal(&m_GCStopCond);
   pthread_join(m_GCThread, NULL);
   
   // XXX There's some weird bug here causing this
   // to hangup on Windows. This might be either something
   // bigger, or some problem in pthread-win32. As this is
   // the application cleanup section, this can be temporarily
   // tolerated with simply exit the application without cleanup,
   // counting on that the system will take care of it anyway.
#ifndef WIN32
   pthread_mutex_destroy(&m_GCStopLock);
   pthread_cond_destroy(&m_GCStopCond);
#endif

   m_bGCStatus = false;

   // Global destruction code
   #ifdef WIN32
      WSACleanup();
   #endif

   return 0;
}

SRTSOCKET CUDTUnited::generateSocketID(bool for_group)
{
    int sockval = m_SocketIDGenerator - 1;

    // First problem: zero-value should be avoided by various reasons.

    if (sockval <= 0)
    {
        // We have a rollover on the socket value, so
        // definitely we haven't made the Columbus mistake yet.
        m_SocketIDGenerator = MAX_SOCKET_VAL-1;
    }

    // Check all sockets if any of them has this value.
    // Socket IDs are begin created this way:
    //
    //                              Initial random
    //                              |
    //                             |
    //                            |
    //                           |
    // ...
    // The only problem might be if the number rolls over
    // and reaches the same value from the opposite side.
    // This is still a valid socket value, but this time
    // we have to check, which sockets have been used already.
    if ( sockval == m_SocketIDGenerator_init )
    {
        // Mark that since this point on the checks for
        // whether the socket ID is in use must be done.
        m_SocketIDGenerator_init = 0;
    }

    // This is when all socket numbers have been already used once.
    // This may happen after many years of running an application
    // constantly when the connection breaks and gets restored often.
    if ( m_SocketIDGenerator_init == 0 )
    {
        int startval = sockval;
        for (;;) // Roll until an unused value is found
        {
            bool exists = false;
            {
                CGuard cg(m_ControlLock);
                exists = for_group ?
                    m_Groups.count(sockval | SRTGROUP_MASK)
                 :
                    m_Sockets.count(sockval);
            }

            if (exists)
            {
                // The socket value is in use.
                --sockval;
                if (sockval <= 0)
                    sockval = MAX_SOCKET_VAL-1;

                // Before continuing, check if we haven't rolled back to start again
                // This is virtually impossible, so just make an RTI error.
                if (sockval == startval)
                {
                    // Of course, we don't lack memory, but actually this is so impossible
                    // that a complete memory extinction is much more possible than this.
                    // So treat this rather as a formal fallback for something that "should
                    // never happen". This should make the socket creation functions, from
                    // socket_create and accept, return this error.

                    m_SocketIDGenerator = sockval+1; // so that any next call will cause the same error
                    throw CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0);
                }

                // try again, if this is a free socket
                continue;
            }

            // No socket found, this ID is free to use
            m_SocketIDGenerator = sockval;
            break;
        }
    }
    else
    {
        m_SocketIDGenerator = sockval;
    }

    // The socket value counter remains with the value rolled
    // without the group bit set; only the returned value may have
    // the group bit set.

    if (for_group)
        sockval = m_SocketIDGenerator | SRTGROUP_MASK;
    else
        sockval = m_SocketIDGenerator;

    LOGC(mglog.Debug) << "generateSocketID: " << (for_group ? "(group)" : "") << ": " << sockval;

    return sockval;
}

SRTSOCKET CUDTUnited::newSocket(CUDTSocket** pps)
{
    CUDTSocket* ns = NULL;

    try
    {
        ns = new CUDTSocket;
    }
    catch (...)
    {
        delete ns;
        throw CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0);
    }

    {
        CGuard guard(m_IDLock);
        ns->m_SocketID = generateSocketID();
    }

    ns->m_Status = SRTS_INIT;
    ns->m_ListenSocket = 0;
    ns->m_Core.m_SocketID = ns->m_SocketID;
    // The "Socket type" is deprecated. For the sake of
    // HSv4 there will be only a "socket type" field set
    // in the handshake, always to UDT_DGRAM.
    //ns->m_Core.m_iSockType = (type == SOCK_STREAM) ? UDT_STREAM : UDT_DGRAM;
    ns->m_Core.m_pCache = m_pCache;

    // protect the m_Sockets structure.
    CGuard cs(m_ControlLock);
    try
    {
        LOGC(mglog.Debug)
            << CONID(ns->m_SocketID)
            << "newSocket: mapping socket "
            << ns->m_SocketID;
        m_Sockets[ns->m_SocketID] = ns;
    }
    catch (...)
    {
        //failure and rollback
        delete ns;
        ns = NULL;
    }

    if (!ns)
        throw CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0);

    if (pps)
        *pps = ns;

    return ns->m_SocketID;
}

int CUDTUnited::newConnection(const SRTSOCKET listen, const sockaddr_any& peer, CHandShake* hs, const CPacket& hspkt)
{
    CUDTSocket* ns = NULL;
    CUDTSocket* ls = locateSocket(listen);

    if (!ls)
    {
        LOGC(mglog.Error) << "newConnection: the listening socket %" << listen << " does not exist";
        return -1;
    }

    LOGC(mglog.Debug) << "newConnection: creating new socket after listener %" << listen << " contacted with backlog=" << ls->m_uiBackLog;

    // if this connection has already been processed
    if ((ns = locatePeer(peer, hs->m_iID, hs->m_iISN)) != NULL)
    {
        if (ns->m_Core.m_bBroken)
        {
            LOGC(mglog.Debug) << "newConnection: located a broken peer %" << hs->m_iID << " - discarding.";
            // last connection from the "peer" address has been broken
            ns->m_Status = SRTS_CLOSED;
            ns->m_TimeStamp = CTimer::getTime();

            CGuard::enterCS(ls->m_AcceptLock);
            ls->m_QueuedSockets.erase(ns->m_SocketID);
            ls->m_AcceptSockets.erase(ns->m_SocketID);
            CGuard::leaveCS(ls->m_AcceptLock);
        }
        else
        {
            // connection already exist, this is a repeated connection request
            // respond with existing HS information
            LOGC(mglog.Debug) << "newConnection: located a WORKING peer %" << hs->m_iID << " - ADAPTING.";

            hs->m_iISN = ns->m_Core.m_iISN;
            hs->m_iMSS = ns->m_Core.m_iMSS;
            hs->m_iFlightFlagSize = ns->m_Core.m_iFlightFlagSize;
            hs->m_iReqType = URQ_CONCLUSION;
            hs->m_iID = ns->m_SocketID;

            return 0;

            //except for this situation a new connection should be started
        }
    }
    else
    {
        LOGC(mglog.Debug) << "newConnection: NOT located any peer %" << hs->m_iID << " - resuming with initial connection.";
    }

    // exceeding backlog, refuse the connection request
    if (ls->m_QueuedSockets.size() >= ls->m_uiBackLog)
    {
        LOGC(mglog.Error) << "newConnection: The incoming " << ls->m_QueuedSockets.size() << "-th connection exceeds the backlog=" << ls->m_uiBackLog;
        return -1;
    }

    try
    {
        ns = new CUDTSocket(ls->core());
        ns->m_PeerAddr = peer; // Take the sa_family value as a good deal.
    }
    catch (...)
    {
        LOGC(mglog.Error) << "newConnection: encountered EXCEPTION when creating a socket - connection will be rejected";
        delete ns;
        return -1;
    }

    try
    {
        CGuard l_idlock(m_IDLock);
        ns->m_SocketID = generateSocketID();
    }
    catch (CUDTException& e)
    {
        LOGC(mglog.Fatal).form("newConnection: IPE: all sockets occupied? Last gen=%d", m_SocketIDGenerator);
        // generateSocketID throws exception, which can be naturally handled
        // when the call is derived from the API call, but here it's called
        // internally in response to receiving a handshake. It must be handled
        // here and turned into an erroneous return value.
        delete ns;
        return -1;
    }

    ns->m_ListenSocket = listen;
    ns->m_Core.m_SocketID = ns->m_SocketID;
    ns->m_PeerID = hs->m_iID;
    ns->m_iISN = hs->m_iISN;

    LOGC(mglog.Debug) << "newConnection: DATA: lsnid=" << listen << " id=" << ns->m_Core.m_SocketID << " peerid=" << ns->m_PeerID << " ISN=" << ns->m_iISN;

    int error = 0;

    // These can throw exception only when the memory allocation failed.
    // CUDT::connect() translates exception into CUDTException.
    // CUDT::open() may only throw original std::bad_alloc from new.
    // This is only to make the library extra safe (when your machine lacks
    // memory, it will continue to work, but fail to accept connection).
    try
    {
        // This assignment must happen b4 the call to CUDT::connect() because
        // this call causes sending the SRT Handshake through this socket.
        // Without this mapping the socket cannot be found and therefore
        // the SRT Handshake message would fail.
        LOGC(mglog.Debug).form(
                "newConnection: incoming %s, mapping socket %d\n",
                SockaddrToString(peer).c_str(), ns->m_SocketID);
        {
            CGuard cg(m_ControlLock);
            m_Sockets[ns->m_SocketID] = ns;
        }

        // bind to the same addr of listening socket
        ns->m_Core.open();
        updateListenerMux(ns, ls);
        ns->m_Core.acceptAndRespond(peer, hs, hspkt);
    }
    catch (...)
    {
        // The mapped socket should be now unmapped to preserve the situation that
        // was in the original UDT code.
        // In SRT additionally the acceptAndRespond() function (it was called probably
        // connect() in UDT code) may fail, in which case this socket should not be
        // further processed and should be removed.
        {
            CGuard cg(m_ControlLock);
            m_Sockets.erase(ns->m_SocketID);
        }
        error = 1;
        LOGC(mglog.Debug).form(
                "newConnection: error while accepting, connection rejected");
        goto ERR_ROLLBACK;
    }

    ns->m_Status = SRTS_CONNECTED;

    // copy address information of local node
    // Precisely, what happens here is:
    // - Get the IP address and port from the system database
    ns->m_Core.m_pSndQueue->m_pChannel->getSockAddr(Ref(ns->m_SelfAddr));
    // - OVERWRITE just the IP address itself by a value taken from piSelfIP
    // (the family is used exactly as the one taken from what has been returned
    // by getsockaddr)
    CIPAddress::pton(Ref(ns->m_SelfAddr), ns->m_Core.m_piSelfIP, ns->m_SelfAddr.family());

    // protect the m_Sockets structure.
    CGuard::enterCS(m_ControlLock);
    try
    {
        LOGC(mglog.Debug).form(
                "newConnection: mapping peer %d to that socket (%d)\n",
                ns->m_PeerID, ns->m_SocketID);
        m_PeerRec[ns->getPeerSpec()].insert(ns->m_SocketID);
    }
    catch (...)
    {
        LOGC(mglog.Error) << "newConnection: error when mapping peer!";
        error = 2;
    }
    CGuard::leaveCS(m_ControlLock);

    CGuard::enterCS(ls->m_AcceptLock);
    try
    {
        ls->m_QueuedSockets.insert(ns->m_SocketID);
    }
    catch (...)
    {
        LOGC(mglog.Error) << "newConnection: error when queuing socket!";
        error = 3;
    }
    CGuard::leaveCS(ls->m_AcceptLock);

    // acknowledge users waiting for new connections on the listening socket
    m_EPoll.update_events(listen, ls->m_Core.m_sPollID, UDT_EPOLL_IN, true);

    CTimer::triggerEvent();

ERR_ROLLBACK:
    // XXX the exact value of 'error' is ignored
    if (error > 0)
    {
        ns->m_Core.close();
        ns->m_Status = SRTS_CLOSED;
        ns->m_TimeStamp = CTimer::getTime();

        return -1;
    }

    if (ns->m_IncludedGroup)
    {
        // XXX this might require another check of group type.
        // FOr redundancy group, at least, update the status in the group
        CUDTGroup* g = ns->m_IncludedGroup;
        CGuard glock(g->m_GroupLock);

        // Update the status in the group so that the next
        // operation can include the socket in the group operation.
        CUDTGroup::gli_t gi = ns->m_IncludedIter;
        gi->sndstate = CUDTGroup::GST_IDLE;
        gi->rcvstate = CUDTGroup::GST_IDLE;
        gi->laststatus = SRTS_CONNECTED;
    }

    // wake up a waiting accept() call
    pthread_mutex_lock(&(ls->m_AcceptLock));
    pthread_cond_signal(&(ls->m_AcceptCond));
    pthread_mutex_unlock(&(ls->m_AcceptLock));

    return 1;
}

SRT_SOCKSTATUS CUDTUnited::getStatus(const SRTSOCKET u)
{
    // protects the m_Sockets structure
    CGuard cg(m_ControlLock);

    sockets_t::iterator i = m_Sockets.find(u);

    if (i == m_Sockets.end())
    {
        if (m_ClosedSockets.find(u) != m_ClosedSockets.end())
            return SRTS_CLOSED;

        return SRTS_NONEXIST;
    }
    return i->second->getStatus();
}

int CUDTUnited::bind(CUDTSocket* s, const sockaddr_any& name)
{
   CGuard cg(s->m_ControlLock);

   // cannot bind a socket more than once
   if (s->m_Status != SRTS_INIT)
      throw CUDTException(MJ_NOTSUP, MN_NONE, 0);

   s->m_Core.open();
   updateMux(s, name);
   s->m_Status = SRTS_OPENED;

   // copy address information of local node
   s->m_Core.m_pSndQueue->m_pChannel->getSockAddr(Ref(s->m_SelfAddr));

   return 0;
}

int CUDTUnited::bind(CUDTSocket* s, int udpsock)
{
   CGuard cg(s->m_ControlLock);

   // cannot bind a socket more than once
   if (s->m_Status != SRTS_INIT)
      throw CUDTException(MJ_NOTSUP, MN_NONE, 0);

   sockaddr_any name;
   socklen_t namelen = sizeof name; // max of inet and inet6

   // This will preset the sa_family as well; the
   // namelen is given simply large enough for any
   // family here.
   if (::getsockname(udpsock, &name.sa, &namelen) == -1)
      throw CUDTException(MJ_NOTSUP, MN_INVAL);

   // Successfully extracted, so update the size
   name.len = namelen;

   s->m_Core.open();
   updateMux(s, name, &udpsock);
   s->m_Status = SRTS_OPENED;

   // copy address information of local node
   s->m_Core.m_pSndQueue->m_pChannel->getSockAddr(Ref(s->m_SelfAddr));

   return 0;
}

int CUDTUnited::listen(const SRTSOCKET u, int backlog)
{
   if (backlog <= 0 )
      throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

   // Don't search for the socket if it's already -1;
   // this never is a valid socket.
   if ( u == UDT::INVALID_SOCK )
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   CUDTSocket* s = locateSocket(u);
   if (!s)
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   CGuard cg(s->m_ControlLock);

   // NOTE: since now the socket is protected against simultaneous access.
   // In the meantime the socket might have been closed, which means that
   // it could have changed the state. It could be also set listen in another
   // thread, so check it out.

   // do nothing if the socket is already listening
   if (s->m_Status == SRTS_LISTENING)
      return 0;

   // a socket can listen only if is in OPENED status
   if (s->m_Status != SRTS_OPENED)
      throw CUDTException(MJ_NOTSUP, MN_ISUNBOUND, 0);

   // [[using assert(s->m_Status == OPENED)]];

   // listen is not supported in rendezvous connection setup
   if (s->m_Core.m_bRendezvous)
      throw CUDTException(MJ_NOTSUP, MN_ISRENDEZVOUS, 0);

   s->m_uiBackLog = backlog;

   // [[using assert(s->m_Status == OPENED)]]; // (still, unchanged)

   s->m_Core.setListenState();  // propagates CUDTException,
                                // if thrown, remains in OPENED state if so.
   s->m_Status = SRTS_LISTENING;

   return 0;
}

SRTSOCKET CUDTUnited::accept(const SRTSOCKET listen, sockaddr* addr, int* addrlen)
{
   if ((addr) && (!addrlen))
      throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

   CUDTSocket* ls = locateSocket(listen);

   if (ls == NULL)
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   // the "listen" socket must be in LISTENING status
   if (ls->m_Status != SRTS_LISTENING)
      throw CUDTException(MJ_NOTSUP, MN_NOLISTEN, 0);

   // no "accept" in rendezvous connection setup
   if (ls->m_Core.m_bRendezvous)
      throw CUDTException(MJ_NOTSUP, MN_ISRENDEZVOUS, 0);

   SRTSOCKET u = CUDT::INVALID_SOCK;
   bool accepted = false;

   // !!only one conection can be set up each time!!
   while (!accepted)
   {
       CGuard cg(ls->m_AcceptLock);

       if ((ls->m_Status != SRTS_LISTENING) || ls->m_Core.m_bBroken)
       {
           // This socket has been closed.
           accepted = true;
       }
       else if (ls->m_QueuedSockets.size() > 0)
       {
           // XXX Actually this should at best be something like that:
           // set<SRTSOCKET>::iterator b = ls->m_QueuedSockets.begin();
           // u = *b;
           // ls->m_QueuedSockets.erase(b);
           // ls->m_pAcceptSockets.insert(u);
           // It is also questionable why m_pQueuedSockets should be of type 'set'.
           // There's no quick-searching capabilities of that container used anywhere except
           // checkBrokenSockets and garbageCollect, which aren't performance-critical,
           // whereas it's mainly used for getting the first element and iterating
           // over elements, which is slow in case of std::set. It's also doubtful
           // as to whether the sorting capability of std::set is properly used;
           // the first is taken here, which is actually the socket with lowest
           // possible descriptor value (as default operator< and ascending sorting
           // used for std::set<SRTSOCKET> where SRTSOCKET=int).

           u = *(ls->m_QueuedSockets.begin());
           // why suggest the position - it is std::set!
           ls->m_AcceptSockets.insert(ls->m_AcceptSockets.end(), u);
           ls->m_QueuedSockets.erase(ls->m_QueuedSockets.begin());
           accepted = true;
       }
       else if (!ls->m_Core.m_bSynRecving)
       {
           accepted = true;
       }

       if (!accepted && (ls->m_Status == SRTS_LISTENING))
           pthread_cond_wait(&(ls->m_AcceptCond), &(ls->m_AcceptLock));

       if (ls->m_QueuedSockets.empty())
           m_EPoll.update_events(listen, ls->m_Core.m_sPollID, UDT_EPOLL_IN, false);
   }

   if (u == CUDT::INVALID_SOCK)
   {
      // non-blocking receiving, no connection available
      if (!ls->m_Core.m_bSynRecving)
         throw CUDTException(MJ_AGAIN, MN_RDAVAIL, 0);

      // listening socket is closed
      throw CUDTException(MJ_NOTSUP, MN_NOLISTEN, 0);
   }

   if ((addr != NULL) && (addrlen != NULL))
   {
      CUDTSocket* s = locateSocket(u);
      if (s == NULL)
         throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

      // Check if LISTENER has the SRTO_GROUPCONNECT flag set,
      // and the already accepted socket has successfully joined
      // the mirror group. If so, RETURN THE GROUP ID, not the socket ID.
      if (ls->m_Core.m_bOPT_GroupConnect && s->m_IncludedGroup)
      {
          u = s->m_IncludedGroup->m_GroupID;
      }

      CGuard cg(s->m_ControlLock);

      // Check if the length of the buffer to fill the name in
      // was large enough.
      int len = s->m_PeerAddr.size();
      if (*addrlen < len)
          throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

      memcpy(addr, &s->m_PeerAddr, len);
      *addrlen = len;
   }

   return u;
}

int CUDTUnited::connect(SRTSOCKET u, const sockaddr* srcname, int srclen, const sockaddr* tarname, int tarlen)
{
    sockaddr_any source_addr(srcname, srclen);
    if (source_addr.len == 0)
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    sockaddr_any target_addr(tarname, tarlen);
    if (target_addr.len == 0)
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    // Check affiliation of the socket. It's now allowed for it to be
    // a group or socket. For a group, add automatically a socket to
    // the group.
    if (u & SRTGROUP_MASK)
    {
        CUDTGroup* g = locateGroup(u);
        if (!g)
            throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

        // Note: forced_isn is ignored when connecting a group.
        // The group manages the ISN by itself ALWAYS, that is,
        // it's generated anew for the very first socket, and then
        // derived by all sockets in the group.
        return groupConnect(Ref(*g), source_addr, target_addr);
    }

    CUDTSocket* s = locateSocket(u);
    if (s == NULL)
        throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

    // For a single socket, just do bind, then connect

    bind(s, source_addr);
    return connectIn(Ref(*s), target_addr, 0);
}

int CUDTUnited::connect(SRTSOCKET u, const sockaddr* name, int namelen, int32_t forced_isn)
{
    sockaddr_any target_addr(name, namelen);
    if (target_addr.len == 0)
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    // Check affiliation of the socket. It's now allowed for it to be
    // a group or socket. For a group, add automatically a socket to
    // the group.
    if (u & SRTGROUP_MASK)
    {
        CUDTGroup* g = locateGroup(u, ERH_THROW);

        // Note: forced_isn is ignored when connecting a group.
        // The group manages the ISN by itself ALWAYS, that is,
        // it's generated anew for the very first socket, and then
        // derived by all sockets in the group.
        sockaddr_any any;
        return groupConnect(Ref(*g), any, target_addr);
    }

    CUDTSocket* s = locateSocket(u);
    if (!s)
        throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

    return connectIn(Ref(*s), target_addr, forced_isn);
}

int CUDTUnited::connectIn(ref_t<CUDTSocket> r_s, const sockaddr_any& target_addr, int32_t forced_isn)
{
    CUDTSocket* s = &*r_s;

    CGuard cg(s->m_ControlLock);

    // a socket can "connect" only if it is in the following states:
    // - OPENED: assume the socket binding parameters are configured
    // - INIT: configure binding parameters here
    // - any other (meaning, already connected): report error

    if (s->m_Status == SRTS_INIT)
    {
        if (s->m_Core.m_bRendezvous)
            throw CUDTException(MJ_NOTSUP, MN_ISRENDUNBOUND, 0);

        // If bind() was done first on this socket, then the
        // socket will not perform this step. This actually does the
        // same thing as bind() does, just with empty address so that
        // the binding parameters are autoselected.

        s->m_Core.open();
        sockaddr_any autoselect_sa (target_addr.family());
        // This will create such a sockaddr_any that
        // will return true from empty(). 
        updateMux(s, autoselect_sa);  // <<---- updateMux
        // -> C(Snd|Rcv)Queue::init
        // -> pthread_create(...C(Snd|Rcv)Queue::worker...)
        s->m_Status = SRTS_OPENED;
    }
    else if (s->m_Status != SRTS_OPENED)
        throw CUDTException(MJ_NOTSUP, MN_ISCONNECTED, 0);

    // connect_complete() may be called before connect() returns.
    // So we need to update the status before connect() is called,
    // otherwise the status may be overwritten with wrong value
    // (CONNECTED vs. CONNECTING).
    s->m_Status = SRTS_CONNECTING;

    /* 
     * In blocking mode, connect can block for up to 30 seconds for
     * rendez-vous mode. Holding the s->m_ControlLock prevent close
     * from cancelling the connect
     */
    try
    {
        // InvertedGuard unlocks in the constructor, then locks in the
        // destructor, no matter if an exception has fired.
        InvertedGuard l_unlocker( s->m_Core.m_bSynRecving ? &s->m_ControlLock : 0 );
        s->m_Core.startConnect(target_addr, forced_isn);
    }
    catch (CUDTException& e) // Interceptor, just to change the state.
    {
        s->m_Status = SRTS_OPENED;
        throw e;
    }

    // record peer address
    s->m_PeerAddr = target_addr;

    // CGuard destructor will delete cg and unlock s->m_ControlLock

    return 0;
}

void CUDTUnited::connect_complete(const SRTSOCKET u)
{
   CUDTSocket* s = locateSocket(u);
   if (!s)
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   // copy address information of local node
   // the local port must be correctly assigned BEFORE CUDT::startConnect(),
   // otherwise if startConnect() fails, the multiplexer cannot be located
   // by garbage collection and will cause leak
   s->m_Core.m_pSndQueue->m_pChannel->getSockAddr(Ref(s->m_SelfAddr));
   CIPAddress::pton(Ref(s->m_SelfAddr), s->m_Core.m_piSelfIP, s->m_SelfAddr.family());

   s->m_Status = SRTS_CONNECTED;
}

int CUDTUnited::close(const SRTSOCKET u)
{
    if (u & SRTGROUP_MASK)
    {
        CUDTGroup* g = locateGroup(u);
        if (!g)
            throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

        g->close();
        deleteGroup(g);
    }
    CUDTSocket* s = locateSocket(u);
    if (!s)
        throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

    return close(s);
}

int CUDTUnited::close(CUDTSocket* s)
{

   LOGC(mglog.Debug) << s->m_Core.CONID() << " CLOSE. Acquiring control lock";

   CGuard socket_cg(s->m_ControlLock);

   LOGC(mglog.Debug) << s->m_Core.CONID() << " CLOSING (removing from listening, closing CUDT)";

   bool synch_close_snd = s->m_Core.m_bSynSending;
   //bool synch_close_rcv = s->m_Core.m_bSynRecving;

   int id = s->m_SocketID;

   if (s->m_Status == SRTS_LISTENING)
   {
      if (s->m_Core.m_bBroken)
         return 0;

      s->m_TimeStamp = CTimer::getTime();
      s->m_Core.m_bBroken = true;

      // NOTE: (changed by Sektor)
      // Leave all the closing activities for garbageCollect to happen,
      // however remove the listener from the RcvQueue IMMEDIATELY.
      // This is because the listener socket is useless anyway and should
      // not be used for anything NEW since now.

      // But there's no reason to destroy the world by occupying the
      // listener slot in the RcvQueue.

      LOGC(mglog.Debug) << s->m_Core.CONID() << " CLOSING (removing listener immediately)";
      {
          CGuard cg(s->m_Core.m_ConnectionLock);
          s->m_Core.m_bListening = false;
          s->m_Core.m_pRcvQueue->removeListener(&s->core());
      }

      // broadcast all "accept" waiting
      pthread_mutex_lock(&(s->m_AcceptLock));
      pthread_cond_broadcast(&(s->m_AcceptCond));
      pthread_mutex_unlock(&(s->m_AcceptLock));

   }
   else
   {
       s->m_Core.close();

       // synchronize with garbage collection.
       LOGC(mglog.Debug) << "%" << id << " CUDT::close done. GLOBAL CLOSE: " << s->m_Core.CONID() << ". Acquiring GLOBAL control lock";
       CGuard manager_cg(m_ControlLock);

       // since "s" is located before m_ControlLock, locateSocket it again in case
       // it became invalid
       sockets_t::iterator i = m_Sockets.find(id);
       if ((i == m_Sockets.end()) || (i->second->m_Status == SRTS_CLOSED))
           return 0;
       s = i->second;

       s->m_Status = SRTS_CLOSED;

       // a socket will not be immediated removed when it is closed
       // in order to prevent other methods from accessing invalid address
       // a timer is started and the socket will be removed after approximately
       // 1 second
       s->m_TimeStamp = CTimer::getTime();

       m_Sockets.erase(s->m_SocketID);
       m_ClosedSockets.insert(pair<SRTSOCKET, CUDTSocket*>(s->m_SocketID, s));

       CTimer::triggerEvent();
   }

   LOGC(mglog.Debug) << "%" << id << ": GLOBAL: CLOSING DONE";

   // Check if the ID is still in closed sockets before you access it
   // (the last triggerEvent could have deleted it).
   if ( synch_close_snd )
   {
#if SRT_ENABLE_CLOSE_SYNCH

       LOGC(mglog.Debug) << "%" << id << " GLOBAL CLOSING: sync-waiting for releasing sender resources...";
       for (;;)
       {
           CSndBuffer* sb = s->m_Core.m_pSndBuffer;

           // Disconnected from buffer - nothing more to check.
           if (!sb)
           {
               LOGC(mglog.Debug) << "%" << id << " GLOBAL CLOSING: sending buffer disconnected. Allowed to close.";
               break;
           }

           // Sender buffer empty
           if (sb->getCurrBufSize() == 0)
           {
               LOGC(mglog.Debug) << "%" << id << " GLOBAL CLOSING: sending buffer depleted. Allowed to close.";
               break;
           }

           // Ok, now you are keeping GC thread hands off the internal data.
           // You can check then if it has already deleted the socket or not.
           // The socket is either in m_ClosedSockets or is already gone.

           // Done the other way, but still done. You can stop waiting.
           bool isgone = false;
           {
               CGuard manager_cg(m_ControlLock);
               isgone = m_ClosedSockets.count(id) == 0;
           }
           if (!isgone)
           {
               isgone = !s->m_Core.m_bOpened;
           }
           if (isgone)
           {
               LOGC(mglog.Debug) << "%" << id << " GLOBAL CLOSING: ... gone in the meantime, whatever. Exiting close().";
               break;
           }

           LOGC(mglog.Debug) << "%" << id << " GLOBAL CLOSING: ... still waiting for any update.";
           CTimer::EWait wt = CTimer::waitForEvent();

           if ( wt == CTimer::WT_ERROR )
           {
               LOGC(mglog.Debug) << "GLOBAL CLOSING: ... ERROR WHEN WAITING FOR EVENT. Exiting close() to prevent hangup.";
               break;
           }

           // Continue waiting in case when an event happened or 1s waiting time passed for checkpoint.
       }
#endif
   }

   /*
      This code is PUT ASIDE for now.
      Most likely this will be never required.
      It had to hold the closing activity until the time when the receiver buffer is depleted.
      However the closing of the socket should only happen when the receiver has received
      an information about that the reading is no longer possible (error report from recv/recvfile).
      When this happens, the receiver buffer is definitely depleted already and there's no need to check
      anything.

      Should there appear any other conditions in future under which the closing process should be
      delayed until the receiver buffer is empty, this code can be filled here.

   if ( synch_close_rcv )
   {
   ...
   }
   */

   return 0;
}

void CUDTUnited::getpeername(const SRTSOCKET u, sockaddr* name, int* namelen)
{
    if (!name || !namelen)
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

   if (getStatus(u) != SRTS_CONNECTED)
      throw CUDTException(MJ_CONNECTION, MN_NOCONN, 0);

   CUDTSocket* s = locateSocket(u);

   if (!s)
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   if (!s->m_Core.m_bConnected || s->m_Core.m_bBroken)
      throw CUDTException(MJ_CONNECTION, MN_NOCONN, 0);

   int len = s->m_PeerAddr.size();
   if (*namelen < len)
       throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

   memcpy(name, &s->m_PeerAddr.sa, len);
   *namelen = len;
}

void CUDTUnited::getsockname(const SRTSOCKET u, sockaddr* name, int* namelen)
{
    if (!name || !namelen)
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

   CUDTSocket* s = locateSocket(u);

   if (!s)
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   if (s->m_Core.m_bBroken)
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);

   if (s->m_Status == SRTS_INIT)
      throw CUDTException(MJ_CONNECTION, MN_NOCONN, 0);

   int len = s->m_SelfAddr.size();
   if (*namelen < len)
       throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

   memcpy(name, &s->m_SelfAddr.sa, len);
   *namelen = len;
}

int CUDTUnited::select(
   ud_set* readfds, ud_set* writefds, ud_set* exceptfds, const timeval* timeout)
{
   uint64_t entertime = CTimer::getTime();

   uint64_t to;
   if (!timeout)
      to = 0xFFFFFFFFFFFFFFFFULL;
   else
      to = timeout->tv_sec * 1000000 + timeout->tv_usec;

   // initialize results
   int count = 0;
   set<SRTSOCKET> rs, ws, es;

   // retrieve related UDT sockets
   vector<CUDTSocket*> ru, wu, eu;
   CUDTSocket* s;
   if (readfds)
      for (set<SRTSOCKET>::iterator i1 = readfds->begin();
         i1 != readfds->end(); ++ i1)
      {
         if (getStatus(*i1) == SRTS_BROKEN)
         {
            rs.insert(*i1);
            ++ count;
         }
         else if (!(s = locateSocket(*i1)))
            throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);
         else
            ru.push_back(s);
      }
   if (writefds)
      for (set<SRTSOCKET>::iterator i2 = writefds->begin();
         i2 != writefds->end(); ++ i2)
      {
         if (getStatus(*i2) == SRTS_BROKEN)
         {
            ws.insert(*i2);
            ++ count;
         }
         else if (!(s = locateSocket(*i2)))
            throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);
         else
            wu.push_back(s);
      }
   if (exceptfds)
      for (set<SRTSOCKET>::iterator i3 = exceptfds->begin();
         i3 != exceptfds->end(); ++ i3)
      {
         if (getStatus(*i3) == SRTS_BROKEN)
         {
            es.insert(*i3);
            ++ count;
         }
         else if (!(s = locateSocket(*i3)))
            throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);
         else
            eu.push_back(s);
      }

   do
   {
      // query read sockets
      for (vector<CUDTSocket*>::iterator j1 = ru.begin(); j1 != ru.end(); ++ j1)
      {
         s = *j1;

         if ((s->m_Core.m_bConnected
               && s->m_Core.m_pRcvBuffer->isRcvDataReady()
            )
            || (!s->m_Core.m_bListening
               && (s->m_Core.m_bBroken || !s->m_Core.m_bConnected))
            || (s->m_Core.m_bListening && (s->m_QueuedSockets.size() > 0))
            || (s->m_Status == SRTS_CLOSED))
         {
            rs.insert(s->m_SocketID);
            ++ count;
         }
      }

      // query write sockets
      for (vector<CUDTSocket*>::iterator j2 = wu.begin(); j2 != wu.end(); ++ j2)
      {
         s = *j2;

         if ((s->m_Core.m_bConnected
               && (s->m_Core.m_pSndBuffer->getCurrBufSize()
                  < s->m_Core.m_iSndBufSize))
            || s->m_Core.m_bBroken
            || !s->m_Core.m_bConnected
            || (s->m_Status == SRTS_CLOSED))
         {
            ws.insert(s->m_SocketID);
            ++ count;
         }
      }

      // query exceptions on sockets
      for (vector<CUDTSocket*>::iterator j3 = eu.begin(); j3 != eu.end(); ++ j3)
      {
         // check connection request status, not supported now
      }

      if (0 < count)
         break;

      CTimer::waitForEvent();
   } while (to > CTimer::getTime() - entertime);

   if (readfds)
      *readfds = rs;

   if (writefds)
      *writefds = ws;

   if (exceptfds)
      *exceptfds = es;

   return count;
}

int CUDTUnited::selectEx(
   const vector<SRTSOCKET>& fds,
   vector<SRTSOCKET>* readfds,
   vector<SRTSOCKET>* writefds,
   vector<SRTSOCKET>* exceptfds,
   int64_t msTimeOut)
{
   uint64_t entertime = CTimer::getTime();

   uint64_t to;
   if (msTimeOut >= 0)
      to = msTimeOut * 1000;
   else
      to = 0xFFFFFFFFFFFFFFFFULL;

   // initialize results
   int count = 0;
   if (readfds)
      readfds->clear();
   if (writefds)
      writefds->clear();
   if (exceptfds)
      exceptfds->clear();

   do
   {
      for (vector<SRTSOCKET>::const_iterator i = fds.begin();
         i != fds.end(); ++ i)
      {
         CUDTSocket* s = locateSocket(*i);

         if ((!s) || s->m_Core.m_bBroken || (s->m_Status == SRTS_CLOSED))
         {
            if (exceptfds)
            {
               exceptfds->push_back(*i);
               ++ count;
            }
            continue;
         }

         if (readfds)
         {
            if ((s->m_Core.m_bConnected
                  && s->m_Core.m_pRcvBuffer->isRcvDataReady()
               )
               || (s->m_Core.m_bListening
                  && (s->m_QueuedSockets.size() > 0)))
            {
               readfds->push_back(s->m_SocketID);
               ++ count;
            }
         }

         if (writefds)
         {
            if (s->m_Core.m_bConnected
               && (s->m_Core.m_pSndBuffer->getCurrBufSize()
                  < s->m_Core.m_iSndBufSize))
            {
               writefds->push_back(s->m_SocketID);
               ++ count;
            }
         }
      }

      if (count > 0)
         break;

      CTimer::waitForEvent();
   } while (to > CTimer::getTime() - entertime);

   return count;
}

int CUDTUnited::epoll_create()
{
   return m_EPoll.create();
}

int CUDTUnited::epoll_add_usock(
   const int eid, const SRTSOCKET u, const int* events)
{
   CUDTSocket* s = locateSocket(u);
   int ret = -1;
   if (s)
   {
      ret = m_EPoll.add_usock(eid, u, events);
      s->m_Core.addEPoll(eid);
   }
   else
   {
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL);
   }

   return ret;
}

int CUDTUnited::epoll_add_ssock(
   const int eid, const SYSSOCKET s, const int* events)
{
   return m_EPoll.add_ssock(eid, s, events);
}

int CUDTUnited::epoll_update_usock(
   const int eid, const SRTSOCKET u, const int* events)
{
   CUDTSocket* s = locateSocket(u);
   int ret = -1;
   if (s)
   {
      ret = m_EPoll.update_usock(eid, u, events);
      s->m_Core.addEPoll(eid);
   }
   else
   {
      throw CUDTException(MJ_NOTSUP, MN_SIDINVAL);
   }

   return ret;
}

int CUDTUnited::epoll_update_ssock(
   const int eid, const SYSSOCKET s, const int* events)
{
   return m_EPoll.update_ssock(eid, s, events);
}

int CUDTUnited::epoll_remove_usock(const int eid, const SRTSOCKET u)
{
   int ret = m_EPoll.remove_usock(eid, u);

   CUDTSocket* s = locateSocket(u);
   if (s)
   {
      s->m_Core.removeEPoll(eid);
   }
   //else
   //{
   //   throw CUDTException(MJ_NOTSUP, MN_SIDINVAL);
   //}

   return ret;
}

int CUDTUnited::epoll_remove_ssock(const int eid, const SYSSOCKET s)
{
   return m_EPoll.remove_ssock(eid, s);
}

int CUDTUnited::epoll_wait(
   const int eid,
   set<SRTSOCKET>* readfds,
   set<SRTSOCKET>* writefds,
   int64_t msTimeOut,
   set<SYSSOCKET>* lrfds,
   set<SYSSOCKET>* lwfds)
{
   return m_EPoll.wait(eid, readfds, writefds, msTimeOut, lrfds, lwfds);
}

int CUDTUnited::epoll_release(const int eid)
{
   return m_EPoll.release(eid);
}

CUDTSocket* CUDTUnited::locateSocket(const SRTSOCKET u, ErrorHandling erh)
{
    CGuard cg(m_ControlLock);

    sockets_t::iterator i = m_Sockets.find(u);

    if ((i == m_Sockets.end()) || (i->second->m_Status == SRTS_CLOSED))
    {
        if (erh == ERH_RETURN)
            return NULL;
        throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);
    }

    return i->second;
}

CUDTGroup* CUDTUnited::locateGroup(SRTSOCKET u, ErrorHandling erh)
{
   CGuard cg(m_ControlLock);

   map<SRTSOCKET, CUDTGroup>::iterator i = m_Groups.find(u);
   if ( i == m_Groups.end() )
   {
       if (erh == ERH_THROW)
           throw CUDTException(MJ_NOTSUP, MN_SIDINVAL, 0);
       return NULL;
   }

   return &i->second;
}

CUDTSocket* CUDTUnited::locatePeer(
   const sockaddr_any& peer,
   const SRTSOCKET id,
   int32_t isn)
{
   CGuard cg(m_ControlLock);

   map<int64_t, set<SRTSOCKET> >::iterator i = m_PeerRec.find(
      CUDTSocket::getPeerSpec(id, isn));
   if (i == m_PeerRec.end())
      return NULL;

   for (set<SRTSOCKET>::iterator j = i->second.begin();
      j != i->second.end(); ++ j)
   {
      sockets_t::iterator k = m_Sockets.find(*j);
      // this socket might have been closed and moved m_ClosedSockets
      if (k == m_Sockets.end())
         continue;

      if ( k->second->m_PeerAddr == peer)
      {
         return k->second;
      }
   }

   return NULL;
}

void CUDTUnited::checkBrokenSockets()
{
   CGuard cg(m_ControlLock);

   // set of sockets To Be Closed and To Be Removed
   vector<SRTSOCKET> tbc;
   vector<SRTSOCKET> tbr;

   for (sockets_t::iterator i = m_Sockets.begin();
      i != m_Sockets.end(); ++ i)
   {
       CUDTSocket* s = i->second;

      // LOGC(mglog.Debug).form("checking EXISTING socket: %d\n", i->first);
      // check broken connection
      if (s->m_Core.m_bBroken)
      {
         if (s->m_Status == SRTS_LISTENING)
         {
            uint64_t elapsed = CTimer::getTime() - s->m_TimeStamp;
            // for a listening socket, it should wait an extra 3 seconds
            // in case a client is connecting
            if (elapsed < 3000000) // XXX MAKE A SYMBOLIC CONSTANT HERE!
            {
               // LOGC(mglog.Debug).form("STILL KEEPING socket %d
               // (listener, too early, w8 %fs)\n", i->first,
               // double(elapsed)/1000000);
               continue;
            }
         }
         else if ((s->m_Core.m_pRcvBuffer != NULL)
            // FIXED: calling isRcvDataAvailable() just to get the information
            // whether there are any data waiting in the buffer,
            // NOT WHETHER THEY ARE ALSO READY TO PLAY at the time when
            // this function is called (isRcvDataReady also checks if the
            // available data is "ready to play").
            && s->m_Core.m_pRcvBuffer->isRcvDataAvailable()
            && (s->m_Core.m_iBrokenCounter -- > 0))
         {
            // LOGC(mglog.Debug).form("STILL KEEPING socket (still have data):
            // %d\n", i->first);
            // if there is still data in the receiver buffer, wait longer
            continue;
         }

         // LOGC(mglog.Debug).form("moving socket to CLOSED: %d\n", i->first);

         //close broken connections and start removal timer
         s->m_Status = SRTS_CLOSED;
         s->m_TimeStamp = CTimer::getTime();
         tbc.push_back(i->first);
         m_ClosedSockets[i->first] = s;

         // remove from listener's queue
         sockets_t::iterator ls = m_Sockets.find(s->m_ListenSocket);
         if (ls == m_Sockets.end())
         {
            ls = m_ClosedSockets.find(s->m_ListenSocket);
            if (ls == m_ClosedSockets.end())
               continue;
         }

         CGuard::enterCS(ls->second->m_AcceptLock);
         ls->second->m_QueuedSockets.erase(s->m_SocketID);
         ls->second->m_AcceptSockets.erase(s->m_SocketID);
         CGuard::leaveCS(ls->second->m_AcceptLock);
      }
   }

   for (sockets_t::iterator j = m_ClosedSockets.begin();
      j != m_ClosedSockets.end(); ++ j)
   {
      // LOGC(mglog.Debug).form("checking CLOSED socket: %d\n", j->first);
      if (j->second->m_Core.m_ullLingerExpiration > 0)
      {
         // asynchronous close:
         if ((!j->second->m_Core.m_pSndBuffer)
            || (0 == j->second->m_Core.m_pSndBuffer->getCurrBufSize())
            || (j->second->m_Core.m_ullLingerExpiration <= CTimer::getTime()))
         {
            j->second->m_Core.m_ullLingerExpiration = 0;
            j->second->m_Core.m_bClosing = true;
            j->second->m_TimeStamp = CTimer::getTime();
         }
      }

      // timeout 1 second to destroy a socket AND it has been removed from
      // RcvUList
      if ((CTimer::getTime() - j->second->m_TimeStamp > 1000000)
         && ((!j->second->m_Core.m_pRNode)
            || !j->second->m_Core.m_pRNode->m_bOnList))
      {
         // LOGC(mglog.Debug).form("will unref socket: %d\n", j->first);
         tbr.push_back(j->first);
      }
   }

   // move closed sockets to the ClosedSockets structure
   for (vector<SRTSOCKET>::iterator k = tbc.begin(); k != tbc.end(); ++ k)
      m_Sockets.erase(*k);

   // remove those timeout sockets
   for (vector<SRTSOCKET>::iterator l = tbr.begin(); l != tbr.end(); ++ l)
      removeSocket(*l);
}

void CUDTUnited::removeSocket(const SRTSOCKET u)
{
   sockets_t::iterator i = m_ClosedSockets.find(u);

   // invalid socket ID
   if (i == m_ClosedSockets.end())
      return;

   // decrease multiplexer reference count, and remove it if necessary
   const int mid = i->second->m_iMuxID;

   {
       CGuard cg(i->second->m_AcceptLock);

      // if it is a listener, close all un-accepted sockets in its queue
      // and remove them later
      for (set<SRTSOCKET>::iterator q = i->second->m_QueuedSockets.begin();
         q != i->second->m_QueuedSockets.end(); ++ q)
      {
         m_Sockets[*q]->m_Core.m_bBroken = true;
         m_Sockets[*q]->m_Core.close();
         m_Sockets[*q]->m_TimeStamp = CTimer::getTime();
         m_Sockets[*q]->m_Status = SRTS_CLOSED;
         m_ClosedSockets[*q] = m_Sockets[*q];
         m_Sockets.erase(*q);
      }

   }

   // remove from peer rec
   map<int64_t, set<SRTSOCKET> >::iterator j = m_PeerRec.find(
      i->second->getPeerSpec());
   if (j != m_PeerRec.end())
   {
      j->second.erase(u);
      if (j->second.empty())
         m_PeerRec.erase(j);
   }

   /*
   * Socket may be deleted while still having ePoll events set that would
   * remains forever causing epoll_wait to unblock continuously for inexistent
   * sockets. Get rid of all events for this socket.
   */
   m_EPoll.update_events(u, i->second->m_Core.m_sPollID,
      UDT_EPOLL_IN|UDT_EPOLL_OUT|UDT_EPOLL_ERR, false);

   // delete this one
   LOGC(mglog.Debug) << "GC/removeSocket: closing associated UDT %" << u;
   i->second->m_Core.close();
   LOGC(mglog.Debug) << "GC/removeSocket: DELETING SOCKET %" << u;
   delete i->second;
   m_ClosedSockets.erase(i);

   map<int, CMultiplexer>::iterator m;
   m = m_mMultiplexer.find(mid);
   if (m == m_mMultiplexer.end())
   {
      LOGC(mglog.Fatal) << "IPE: For socket %" << u << " MUXER id=" << mid << " NOT FOUND!";
      return;
   }

   m->second.m_iRefCount --;
   // LOGC(mglog.Debug).form("unrefing underlying socket for %u: %u\n",
   //    u, m->second.m_iRefCount);
   if (0 == m->second.m_iRefCount)
   {
       LOGC(mglog.Debug) << "MUXER id=" << mid << " lost last socket %"
           << u << " - deleting muxer bound to port "
           << m->second.m_pChannel->bindAddressAny().hport();
      m->second.m_pChannel->close();
      delete m->second.m_pSndQueue;
      delete m->second.m_pRcvQueue;
      delete m->second.m_pTimer;
      delete m->second.m_pChannel;
      m_mMultiplexer.erase(m);
   }
}

void CUDTUnited::setError(CUDTException* e)
{
    delete (CUDTException*)pthread_getspecific(m_TLSError);
    pthread_setspecific(m_TLSError, e);
}

CUDTException* CUDTUnited::getError()
{
    if(!pthread_getspecific(m_TLSError))
        pthread_setspecific(m_TLSError, new CUDTException);
    return (CUDTException*)pthread_getspecific(m_TLSError);
}


void CUDTUnited::updateMux(
   CUDTSocket* s, const sockaddr_any& addr, const int* udpsock /*[[nullable]]*/)
{
   CGuard cg(m_ControlLock);

   // Don't try to reuse given address, if udpsock was given.
   // In such a case rely exclusively on that very socket and
   // use it the way as it is configured, of course, create also
   // always a new multiplexer for that very socket.
   if (!udpsock && s->m_Core.m_bReuseAddr)
   {
       int port = addr.hport();

       // find a reusable address
       for (map<int, CMultiplexer>::iterator i = m_mMultiplexer.begin();
               i != m_mMultiplexer.end(); ++ i)
       {
           // Use the "family" value blindly from the address; we
           // need to find an existing multiplexer that binds to the
           // given port in the same family as requested address.
           if ((i->second.m_iFamily == addr.family())
                   && (i->second.m_iMSS == s->m_Core.m_iMSS)
#ifdef SRT_ENABLE_IPOPTS
                   &&  (i->second.m_iIpTTL == s->m_Core.m_iIpTTL)
                   && (i->second.m_iIpToS == s->m_Core.m_iIpToS)
#endif
                   &&  i->second.m_bReusable)
           {
               if (i->second.m_iPort == port)
               {
                   // LOGC(mglog.Debug).form("reusing multiplexer for port
                   // %hd\n", port);
                   // reuse the existing multiplexer
                   ++ i->second.m_iRefCount;
                   s->m_Core.m_pSndQueue = i->second.m_pSndQueue;
                   s->m_Core.m_pRcvQueue = i->second.m_pRcvQueue;
                   s->m_iMuxID = i->second.m_iID;
                   return;
               }
           }
       }
   }

   // a new multiplexer is needed
   CMultiplexer m;
   m.m_iMSS = s->m_Core.m_iMSS;
   m.m_iFamily = addr.family();
#ifdef SRT_ENABLE_IPOPTS
   m.m_iIpTTL = s->m_Core.m_iIpTTL;
   m.m_iIpToS = s->m_Core.m_iIpToS;
#endif
   m.m_iRefCount = 1;
   m.m_bReusable = s->m_Core.m_bReuseAddr;
   m.m_iID = s->m_SocketID;

   m.m_pChannel = new CChannel;
#ifdef SRT_ENABLE_IPOPTS
   m.m_pChannel->setIpTTL(s->m_Core.m_iIpTTL);
   m.m_pChannel->setIpToS(s->m_Core.m_iIpToS);
#endif
   m.m_pChannel->setSndBufSize(s->m_Core.m_iUDPSndBufSize);
   m.m_pChannel->setRcvBufSize(s->m_Core.m_iUDPRcvBufSize);

   try
   {
       if (udpsock)
       {
           // In this case, addr contains the address
           // that has been extracted already from the
           // given socket
           m.m_pChannel->attach(*udpsock, addr);
       }
       else if (addr.empty())
       {
           // The case of previously used case of a NULL address.
           // This here is used to pass family only, in this case
           // just automatically bind to the "0" address to autoselect
           // everything. If at least the IP address is specified,
           // then bind to that address, but still possibly autoselect
           // the outgoing port, if the port was specified as 0.
           m.m_pChannel->open(addr.family());
       }
       else
       {
           m.m_pChannel->open(addr);
       }
   }
   catch (CUDTException& e)
   {
      m.m_pChannel->close();
      delete m.m_pChannel;
      throw e;
   }

   sockaddr_any sa;
   m.m_pChannel->getSockAddr(Ref(sa));
   m.m_iPort = sa.hport();

   m.m_pTimer = new CTimer;

   m.m_pSndQueue = new CSndQueue;
   m.m_pSndQueue->init(m.m_pChannel, m.m_pTimer);
   m.m_pRcvQueue = new CRcvQueue;
   m.m_pRcvQueue->init(
      32, s->m_Core.maxPayloadSize(), m.m_iFamily, 1024,
      m.m_pChannel, m.m_pTimer);

   m_mMultiplexer[m.m_iID] = m;

   s->m_Core.m_pSndQueue = m.m_pSndQueue;
   s->m_Core.m_pRcvQueue = m.m_pRcvQueue;
   s->m_iMuxID = m.m_iID;

   LOGC(mglog.Debug).form(
      "creating new multiplexer for port %i\n", m.m_iPort);
}

// XXX This is actually something completely stupid.
// This function is going to find a multiplexer for the port contained
// in the 'ls' listening socket, by searching through the multiplexer
// container.
//
// Somehow, however, it's not even predicted a situation that the multiplexer
// for that port doesn't exist - that is, this function WILL find the
// multiplexer. How can it be so certain? It's because the listener has
// already created the multiplexer during the call to bind(), so if it
// didn't, this function wouldn't even have a chance to be called.
//
// Why can't then the multiplexer be recorded in the 'ls' listening socket data
// to be accessed immediately, especially when one listener can't bind to more than
// one multiplexer at a time (well, even if it could, there's still no reason why
// this should be extracted by "querying")?
//
// Maybe because the multiplexer container is a map, not a list.
// Why is this then a map? Because it's addressed by MuxID. Why do we need
// mux id? Because we don't have a list... ?
// 
// But what's the multiplexer ID? It's a socket ID for which it was originally created.
//
// Is this then shared? Yes, only between the listener socket and the accepted sockets,
// or in case of "bound" connecting sockets (by binding you can enforce the port number,
// which can be the same for multiple SRT sockets).
// Not shared in case of unbound connecting socket or rendezvous socket.
//
// Ok, in which situation do we need dispatching by mux id? Only when the socket is being
// deleted. How does the deleting procedure know the muxer id? Because it is recorded here
// at the time when it's found, as... the socket ID of the actual listener socket being
// actually the first socket to create the multiplexer, so the multiplexer gets its id.
//
// Still, no reasons found why the socket can't contain a list iterator to a multiplexer
// INSTEAD of m_iMuxID. There's no danger in this solutio because the multiplexer is never
// deleted until there's at least one socket using it.
//
// The multiplexer may even physically be contained in the CUDTUnited object, just track
// the multiple users of it (the listener and the accepted sockets). When deleting, you
// simply "unsubscribe" yourself from the multiplexer, which will unref it and remove the
// list element by the iterator kept by the socket.
void CUDTUnited::updateListenerMux(CUDTSocket* s, const CUDTSocket* ls)
{
   CGuard cg(m_ControlLock);
   int port = ls->m_SelfAddr.hport();

   // find the listener's address
   for (map<int, CMultiplexer>::iterator i = m_mMultiplexer.begin();
      i != m_mMultiplexer.end(); ++ i)
   {
      if (i->second.m_iPort == port)
      {
         LOGC(mglog.Debug).form(
            "updateMux: reusing multiplexer for port %i\n", port);
         // reuse the existing multiplexer
         ++ i->second.m_iRefCount;
         s->m_Core.m_pSndQueue = i->second.m_pSndQueue;
         s->m_Core.m_pRcvQueue = i->second.m_pRcvQueue;
         s->m_iMuxID = i->second.m_iID;
         return;
      }
   }
}

void* CUDTUnited::garbageCollect(void* p)
{
   CUDTUnited* self = (CUDTUnited*)p;

   THREAD_STATE_INIT("SRT Collector");

   CGuard gcguard(self->m_GCStopLock);

   while (!self->m_bClosing)
   {
       INCREMENT_THREAD_ITERATIONS();
       self->checkBrokenSockets();

       //#ifdef WIN32
       //      self->checkTLSValue();
       //#endif

       timeval now;
       timespec timeout;
       gettimeofday(&now, 0);
       timeout.tv_sec = now.tv_sec + 1;
       timeout.tv_nsec = now.tv_usec * 1000;

       pthread_cond_timedwait(
               &self->m_GCStopCond, &self->m_GCStopLock, &timeout);
   }

   // remove all sockets and multiplexers
   CGuard::enterCS(self->m_ControlLock);
   for (sockets_t::iterator i = self->m_Sockets.begin();
      i != self->m_Sockets.end(); ++ i)
   {
      i->second->m_Core.m_bBroken = true;
      i->second->m_Core.close();
      i->second->m_Status = SRTS_CLOSED;
      i->second->m_TimeStamp = CTimer::getTime();
      self->m_ClosedSockets[i->first] = i->second;

      // remove from listener's queue
      sockets_t::iterator ls = self->m_Sockets.find(i->second->m_ListenSocket);
      if (ls == self->m_Sockets.end())
      {
         ls = self->m_ClosedSockets.find(i->second->m_ListenSocket);
         if (ls == self->m_ClosedSockets.end())
            continue;
      }

      CGuard::enterCS(ls->second->m_AcceptLock);
      ls->second->m_QueuedSockets.erase(i->second->m_SocketID);
      ls->second->m_AcceptSockets.erase(i->second->m_SocketID);
      CGuard::leaveCS(ls->second->m_AcceptLock);
   }
   self->m_Sockets.clear();

   for (sockets_t::iterator j = self->m_ClosedSockets.begin();
           j != self->m_ClosedSockets.end(); ++ j)
   {
      j->second->m_TimeStamp = 0;
   }
   CGuard::leaveCS(self->m_ControlLock);

   while (true)
   {
      self->checkBrokenSockets();

      CGuard::enterCS(self->m_ControlLock);
      bool empty = self->m_ClosedSockets.empty();
      CGuard::leaveCS(self->m_ControlLock);

      if (empty)
         break;

      CTimer::sleep();
   }

   THREAD_EXIT();
   return NULL;
}


////////////////////////////////////////////////////////////////////////////////

int CUDT::startup()
{
   return s_UDTUnited.startup();
}

int CUDT::cleanup()
{
   return s_UDTUnited.cleanup();
}

SRTSOCKET CUDT::socket()
{
   if (!s_UDTUnited.m_bGCStatus)
      s_UDTUnited.startup();

   try
   {
      return s_UDTUnited.newSocket();
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return INVALID_SOCK;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
      return INVALID_SOCK;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "socket: UNEXPECTED EXCEPTION: "
         << typeid(ee).name()
         << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return INVALID_SOCK;
   }
}

int CUDT::setError(const CUDTException& e)
{
    s_UDTUnited.setError(new CUDTException(e));
    return SRT_ERROR;
}

int CUDT::setError(CodeMajor mj, CodeMinor mn, int syserr)
{
    s_UDTUnited.setError(new CUDTException(mj, mn, syserr));
    return SRT_ERROR;
}

// This is an internal function; 'type' should be pre-checked if it has a correct value.
// This doesn't have argument of GroupType due to header file conflicts.
CUDTGroup& CUDT::newGroup(int type)
{
    CGuard guard(s_UDTUnited.m_IDLock);
    SRTSOCKET id = s_UDTUnited.generateSocketID(true);

    // Now map the group
    return s_UDTUnited.addGroup(id).id(id).type(SRT_GROUP_TYPE(type));
}

SRTSOCKET CUDT::createGroup(SRT_GROUP_TYPE gt)
{
    // Doing the same lazy-startup as with srt_create_socket()
    if (!s_UDTUnited.m_bGCStatus)
        s_UDTUnited.startup();

    try
    {
        return newGroup(gt).id();
    }
    catch (CUDTException& e)
    {
        return setError(e);
    }
    catch (std::bad_alloc& e)
    {
        return setError(MJ_SYSTEMRES, MN_MEMORY, 0);
    }
}


int CUDT::addSocketToGroup(SRTSOCKET socket, SRTSOCKET group)
{
    // Check if socket and group have been set correctly.
    int32_t sid = socket & ~SRTGROUP_MASK;
    int32_t gm = group & SRTGROUP_MASK;

    if ( sid != socket || gm == 0 )
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    // Find the socket and the group
    CUDTSocket* s = s_UDTUnited.locateSocket(socket);
    CUDTGroup* g = s_UDTUnited.locateGroup(group);

    if (!s || !g)
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    // Check if the socket is already IN SOME GROUP.
    if (s->m_IncludedGroup)
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    if (g->managed())
    {
        // This can be changed as long as the group is empty.
        if (!g->empty())
        {
            return setError(MJ_NOTSUP, MN_INVAL, 0);
        }
        g->managed(false);
    }

    CGuard cg(s->m_ControlLock);

    // Check if the socket already is in the group
    CUDTGroup::gli_t f = g->find(socket);
    if (f != CUDTGroup::gli_NULL())
    {
        // XXX This is internal error. Report it, but continue
        LOGC(mglog.Error) << "IPE (non-fatal): the socket is in the group, but has no clue about it!";
        s->m_IncludedGroup = g;
        s->m_IncludedIter = f;
        return 0;
    }
    s->m_IncludedGroup = g;
    s->m_IncludedIter = g->add(g->prepareData(s));

    return 0;
}

int CUDT::removeSocketFromGroup(SRTSOCKET socket)
{
    CUDTSocket* s = s_UDTUnited.locateSocket(socket);
    if (!s)
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    if (!s->m_IncludedGroup)
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    CGuard grd(s->m_ControlLock);

    s->m_IncludedGroup->remove(socket);
    s->m_IncludedIter = CUDTGroup::gli_NULL();
    s->m_IncludedGroup = NULL;

    return 0;
}

SRTSOCKET CUDT::getGroupOfSocket(SRTSOCKET socket)
{
    CUDTSocket* s = s_UDTUnited.locateSocket(socket);
    if (!s)
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    if (!s->m_IncludedGroup)
        return setError(MJ_NOTSUP, MN_INVAL, 0);

    return s->m_IncludedGroup->id();
}

int CUDT::bind(SRTSOCKET u, const sockaddr* name, int namelen)
{
   try
   {
       sockaddr_any sa (name, namelen);
       if ( sa.len == 0 )
       {
           // This happens if the namelen check proved it to be
           // too small for particular family, or that family is
           // not recognized (is none of AF_INET, AF_INET6).
           // This is a user error.
           return setError(MJ_NOTSUP, MN_INVAL, 0);
       }
       CUDTSocket* s = s_UDTUnited.locateSocket(u);
       if (!s)
           return setError(MJ_NOTSUP, MN_INVAL, 0);

       return s_UDTUnited.bind(s, sa);
   }
   catch (CUDTException& e)
   {
       return setError(e);
   }
   catch (bad_alloc&)
   {
       return setError(MJ_SYSTEMRES, MN_MEMORY, 0);
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "bind: UNEXPECTED EXCEPTION: "
         << typeid(ee).name()
         << ": " << ee.what();
      return setError(MJ_UNKNOWN, MN_NONE, 0);
   }
}

int CUDT::bind(SRTSOCKET u, int udpsock)
{
    try
    {
        CUDTSocket* s = s_UDTUnited.locateSocket(u);
        if (!s)
            return setError(MJ_NOTSUP, MN_INVAL, 0);

        return s_UDTUnited.bind(s, udpsock);
    }
    catch (CUDTException& e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (bad_alloc&)
    {
        s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "bind/udp: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int CUDT::listen(SRTSOCKET u, int backlog)
{
   try
   {
      return s_UDTUnited.listen(u, backlog);
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "listen: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

SRTSOCKET CUDT::accept(SRTSOCKET u, sockaddr* addr, int* addrlen)
{
   try
   {
      return s_UDTUnited.accept(u, addr, addrlen);
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return INVALID_SOCK;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "accept: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return INVALID_SOCK;
   }
}

int CUDT::connect(SRTSOCKET u, const sockaddr* name, int namelen, const sockaddr* tname, int tnamelen)
{
   try
   {
      return s_UDTUnited.connect(u, name, namelen, tname, tnamelen);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "connect: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::connect(SRTSOCKET u, const sockaddr* name, int namelen, int32_t forced_isn)
{
   try
   {
      return s_UDTUnited.connect(u, name, namelen, forced_isn);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "connect: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::close(SRTSOCKET u)
{
   try
   {
      return s_UDTUnited.close(u);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "close: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::getpeername(SRTSOCKET u, sockaddr* name, int* namelen)
{
   try
   {
      s_UDTUnited.getpeername(u, name, namelen);
      return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "getpeername: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::getsockname(SRTSOCKET u, sockaddr* name, int* namelen)
{
   try
   {
      s_UDTUnited.getsockname(u, name, namelen);;
      return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "getsockname: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::getsockopt(SRTSOCKET u, int, SRT_SOCKOPT optname, void* optval, int* optlen)
{
    if (!optval || !optlen)
    {
        return setError(MJ_NOTSUP, MN_INVAL, 0);
    }

    try
    {
        if (u & SRTGROUP_MASK)
        {
            CUDTGroup* g = s_UDTUnited.locateGroup(u, s_UDTUnited.ERH_THROW);
            g->getOpt(optname, optval, Ref(*optlen));
            return 0;
        }
        CUDTSocket* s = s_UDTUnited.locateSocket(u, s_UDTUnited.ERH_THROW);
        s->core().getOpt(optname, optval, Ref(*optlen));
        return 0;
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "getsockopt: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int CUDT::setsockopt(SRTSOCKET u, int, SRT_SOCKOPT optname, const void* optval, int optlen)
{
    if (!optval)
    {
        return setError(MJ_NOTSUP, MN_INVAL, 0);
    }

    try
    {
        if (u & SRTGROUP_MASK)
        {
            CUDTGroup* g = s_UDTUnited.locateGroup(u, s_UDTUnited.ERH_THROW);
            g->setOpt(optname, optval, optlen);
            return 0;
        }

        CUDTSocket* s = s_UDTUnited.locateSocket(u, s_UDTUnited.ERH_THROW);
        s->core().setOpt(optname, optval, optlen);
        return 0;
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "setsockopt: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int CUDT::send(SRTSOCKET u, const char* buf, int len)
{
    SRT_MSGCTRL mctrl = srt_msgctrl_default;
    return sendmsg2(u, buf, len, Ref(mctrl));
}

int CUDT::sendmsg(SRTSOCKET u, const char* buf, int len, int ttl, bool inorder, uint64_t srctime)
{
    SRT_MSGCTRL mctrl = srt_msgctrl_default;
    mctrl.msgttl = ttl;
    mctrl.inorder = inorder;
    mctrl.srctime = srctime;
    return sendmsg2(u, buf, len, Ref(mctrl));
}

int CUDT::sendmsg2(SRTSOCKET u, const char* buf, int len, ref_t<SRT_MSGCTRL> m)
{
    try
    {
        if (u & SRTGROUP_MASK)
        {
            return s_UDTUnited.locateGroup(u, CUDTUnited::ERH_THROW)->send(buf, len, m);
        }

        return s_UDTUnited.locateSocket(u, CUDTUnited::ERH_THROW)->core().sendmsg2(buf, len, m);
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (bad_alloc&)
    {
        s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "sendmsg: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int CUDT::recv(SRTSOCKET u, char* buf, int len)
{
    SRT_MSGCTRL mctrl = srt_msgctrl_default;
    int ret = recvmsg2(u, buf, len, Ref(mctrl));
    return ret;
}

int CUDT::recvmsg(SRTSOCKET u, char* buf, int len, uint64_t& srctime)
{
    SRT_MSGCTRL mctrl = srt_msgctrl_default;
    int ret = recvmsg2(u, buf, len, Ref(mctrl));
    srctime = mctrl.srctime;
    return ret;
}

int CUDT::recvmsg2(SRTSOCKET u, char* buf, int len, ref_t<SRT_MSGCTRL> m)
{
    try
    {
        if (u & SRTGROUP_MASK)
        {
            return s_UDTUnited.locateGroup(u, CUDTUnited::ERH_THROW)->recv(buf, len, m);
        }

        return s_UDTUnited.locateSocket(u, CUDTUnited::ERH_THROW)->core().recvmsg2(buf, len, m);
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "recvmsg: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int64_t CUDT::sendfile(SRTSOCKET u, fstream& ifs, int64_t& offset, int64_t size, int block)
{
    try
    {
        return s_UDTUnited.locateSocket(u, CUDTUnited::ERH_THROW)->core().sendfile(ifs, offset, size, block);
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (bad_alloc&)
    {
        s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "sendfile: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int64_t CUDT::recvfile(SRTSOCKET u, fstream& ofs, int64_t& offset, int64_t size, int block)
{
    try
    {
        return s_UDTUnited.locateSocket(u, CUDTUnited::ERH_THROW)->core().recvfile(ofs, offset, size, block);
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return ERROR;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "recvfile: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return ERROR;
    }
}

int CUDT::select(
   int,
   ud_set* readfds,
   ud_set* writefds,
   ud_set* exceptfds,
   const timeval* timeout)
{
   if ((!readfds) && (!writefds) && (!exceptfds))
   {
      s_UDTUnited.setError(new CUDTException(MJ_NOTSUP, MN_INVAL, 0));
      return ERROR;
   }

   try
   {
      return s_UDTUnited.select(readfds, writefds, exceptfds, timeout);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "select: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::selectEx(
   const vector<SRTSOCKET>& fds,
   vector<SRTSOCKET>* readfds,
   vector<SRTSOCKET>* writefds,
   vector<SRTSOCKET>* exceptfds,
   int64_t msTimeOut)
{
   if ((!readfds) && (!writefds) && (!exceptfds))
   {
      s_UDTUnited.setError(new CUDTException(MJ_NOTSUP, MN_INVAL, 0));
      return ERROR;
   }

   try
   {
      return s_UDTUnited.selectEx(fds, readfds, writefds, exceptfds, msTimeOut);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(new CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "selectEx: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN));
      return ERROR;
   }
}

int CUDT::epoll_create()
{
   try
   {
      return s_UDTUnited.epoll_create();
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_create: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_add_usock(const int eid, const SRTSOCKET u, const int* events)
{
   try
   {
      return s_UDTUnited.epoll_add_usock(eid, u, events);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_add_usock: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_add_ssock(const int eid, const SYSSOCKET s, const int* events)
{
   try
   {
      return s_UDTUnited.epoll_add_ssock(eid, s, events);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_add_ssock: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_update_usock(
   const int eid, const SRTSOCKET u, const int* events)
{
   try
   {
      return s_UDTUnited.epoll_update_usock(eid, u, events);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_update_usock: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_update_ssock(
   const int eid, const SYSSOCKET s, const int* events)
{
   try
   {
      return s_UDTUnited.epoll_update_ssock(eid, s, events);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_update_ssock: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}


int CUDT::epoll_remove_usock(const int eid, const SRTSOCKET u)
{
   try
   {
      return s_UDTUnited.epoll_remove_usock(eid, u);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_remove_usock: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_remove_ssock(const int eid, const SYSSOCKET s)
{
   try
   {
      return s_UDTUnited.epoll_remove_ssock(eid, s);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_remove_ssock: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_wait(
   const int eid,
   set<SRTSOCKET>* readfds,
   set<SRTSOCKET>* writefds,
   int64_t msTimeOut,
   set<SYSSOCKET>* lrfds,
   set<SYSSOCKET>* lwfds)
{
   try
   {
      return s_UDTUnited.epoll_wait(
         eid, readfds, writefds, msTimeOut, lrfds, lwfds);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_wait: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::epoll_release(const int eid)
{
   try
   {
      return s_UDTUnited.epoll_release(eid);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "epoll_release: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

CUDTException& CUDT::getlasterror()
{
   return *s_UDTUnited.getError();
}

int CUDT::perfmon(SRTSOCKET u, CPerfMon* perf, bool clear)
{
   try
   {
       CUDTSocket* s = s_UDTUnited.locateSocket(u, s_UDTUnited.ERH_THROW);
       s->core().sample(perf, clear);
       return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "perfmon: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

int CUDT::bstats(SRTSOCKET u, CBytePerfMon* perf, bool clear)
{
   try
   {
       CUDTSocket* s = s_UDTUnited.locateSocket(u, s_UDTUnited.ERH_THROW);
       s->core().bstats(perf, clear);
       return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "bstats: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return ERROR;
   }
}

CUDT* CUDT::getUDTHandle(SRTSOCKET u)
{
    try
    {
        return &s_UDTUnited.locateSocket(u, CUDTUnited::ERH_THROW)->core();
    }
    catch (CUDTException e)
    {
        s_UDTUnited.setError(new CUDTException(e));
        return NULL;
    }
    catch (std::exception& ee)
    {
        LOGC(mglog.Fatal)
            << "getUDTHandle: UNEXPECTED EXCEPTION: "
            << typeid(ee).name() << ": " << ee.what();
        s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
        return NULL;
    }
}

vector<SRTSOCKET> CUDT::existingSockets()
{
    vector<SRTSOCKET> out;
    for (CUDTUnited::sockets_t::iterator i = s_UDTUnited.m_Sockets.begin();
            i != s_UDTUnited.m_Sockets.end(); ++i)
    {
        out.push_back(i->first);
    }
    return out;
}

SRT_SOCKSTATUS CUDT::getsockstate(SRTSOCKET u)
{
   try
   {
       if (isgroup(u))
       {
           CUDTGroup* g = s_UDTUnited.locateGroup(u, s_UDTUnited.ERH_THROW);
           return g->getStatus();
       }
       return s_UDTUnited.getStatus(u);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return SRTS_NONEXIST;
   }
   catch (std::exception& ee)
   {
      LOGC(mglog.Fatal)
         << "getsockstate: UNEXPECTED EXCEPTION: "
         << typeid(ee).name() << ": " << ee.what();
      s_UDTUnited.setError(new CUDTException(MJ_UNKNOWN, MN_NONE, 0));
      return SRTS_NONEXIST;
   }
}


////////////////////////////////////////////////////////////////////////////////

namespace UDT
{

int startup()
{
   return CUDT::startup();
}

int cleanup()
{
   return CUDT::cleanup();
}

SRTSOCKET socket(int , int , int )
{
   return CUDT::socket();
}

int bind(SRTSOCKET u, const struct sockaddr* name, int namelen)
{
   return CUDT::bind(u, name, namelen);
}

int bind2(SRTSOCKET u, int udpsock)
{
   return CUDT::bind(u, udpsock);
}

int listen(SRTSOCKET u, int backlog)
{
   return CUDT::listen(u, backlog);
}

SRTSOCKET accept(SRTSOCKET u, struct sockaddr* addr, int* addrlen)
{
   return CUDT::accept(u, addr, addrlen);
}

int connect(SRTSOCKET u, const struct sockaddr* name, int namelen)
{
   return CUDT::connect(u, name, namelen, 0);
}

int close(SRTSOCKET u)
{
   return CUDT::close(u);
}

int getpeername(SRTSOCKET u, struct sockaddr* name, int* namelen)
{
   return CUDT::getpeername(u, name, namelen);
}

int getsockname(SRTSOCKET u, struct sockaddr* name, int* namelen)
{
   return CUDT::getsockname(u, name, namelen);
}

int getsockopt(
   SRTSOCKET u, int level, SRT_SOCKOPT optname, void* optval, int* optlen)
{
   return CUDT::getsockopt(u, level, optname, optval, optlen);
}

int setsockopt(
   SRTSOCKET u, int level, SRT_SOCKOPT optname, const void* optval, int optlen)
{
   return CUDT::setsockopt(u, level, optname, optval, optlen);
}

// DEVELOPER API

int connect_debug(
   SRTSOCKET u, const struct sockaddr* name, int namelen, int32_t forced_isn)
{
   return CUDT::connect(u, name, namelen, forced_isn);
}

int send(SRTSOCKET u, const char* buf, int len, int)
{
   return CUDT::send(u, buf, len);
}

int recv(SRTSOCKET u, char* buf, int len, int)
{
   return CUDT::recv(u, buf, len);
}


int sendmsg(
   SRTSOCKET u, const char* buf, int len, int ttl, bool inorder,
   uint64_t srctime)
{
   return CUDT::sendmsg(u, buf, len, ttl, inorder, srctime);
}

int recvmsg(SRTSOCKET u, char* buf, int len, uint64_t& srctime)
{
   return CUDT::recvmsg(u, buf, len, srctime);
}

int recvmsg(SRTSOCKET u, char* buf, int len)
{
   uint64_t srctime;

   return CUDT::recvmsg(u, buf, len, srctime);
}

int64_t sendfile(
   SRTSOCKET u,
   fstream& ifs,
   int64_t& offset,
   int64_t size,
   int block)
{
   return CUDT::sendfile(u, ifs, offset, size, block);
}

int64_t recvfile(
   SRTSOCKET u,
   fstream& ofs,
   int64_t& offset,
   int64_t size,
   int block)
{
   return CUDT::recvfile(u, ofs, offset, size, block);
}

int64_t sendfile2(
   SRTSOCKET u,
   const char* path,
   int64_t* offset,
   int64_t size,
   int block)
{
   fstream ifs(path, ios::binary | ios::in);
   int64_t ret = CUDT::sendfile(u, ifs, *offset, size, block);
   ifs.close();
   return ret;
}

int64_t recvfile2(
   SRTSOCKET u,
   const char* path,
   int64_t* offset,
   int64_t size,
   int block)
{
   fstream ofs(path, ios::binary | ios::out);
   int64_t ret = CUDT::recvfile(u, ofs, *offset, size, block);
   ofs.close();
   return ret;
}

int select(
   int nfds,
   UDSET* readfds,
   UDSET* writefds,
   UDSET* exceptfds,
   const struct timeval* timeout)
{
   return CUDT::select(nfds, readfds, writefds, exceptfds, timeout);
}

int selectEx(
   const vector<SRTSOCKET>& fds,
   vector<SRTSOCKET>* readfds,
   vector<SRTSOCKET>* writefds,
   vector<SRTSOCKET>* exceptfds,
   int64_t msTimeOut)
{
   return CUDT::selectEx(fds, readfds, writefds, exceptfds, msTimeOut);
}

int epoll_create()
{
   return CUDT::epoll_create();
}

int epoll_add_usock(int eid, SRTSOCKET u, const int* events)
{
   return CUDT::epoll_add_usock(eid, u, events);
}

int epoll_add_ssock(int eid, SYSSOCKET s, const int* events)
{
   return CUDT::epoll_add_ssock(eid, s, events);
}

int epoll_update_usock(int eid, SRTSOCKET u, const int* events)
{
   return CUDT::epoll_update_usock(eid, u, events);
}

int epoll_update_ssock(int eid, SYSSOCKET s, const int* events)
{
   return CUDT::epoll_update_ssock(eid, s, events);
}

int epoll_remove_usock(int eid, SRTSOCKET u)
{
   return CUDT::epoll_remove_usock(eid, u);
}

int epoll_remove_ssock(int eid, SYSSOCKET s)
{
   return CUDT::epoll_remove_ssock(eid, s);
}

int epoll_wait(
   int eid,
   set<SRTSOCKET>* readfds,
   set<SRTSOCKET>* writefds,
   int64_t msTimeOut,
   set<SYSSOCKET>* lrfds,
   set<SYSSOCKET>* lwfds)
{
   return CUDT::epoll_wait(eid, readfds, writefds, msTimeOut, lrfds, lwfds);
}

/*

#define SET_RESULT(val, num, fds, it) \
   if (val != NULL) \
   { \
      if (val->empty()) \
      { \
         if (num) *num = 0; \
      } \
      else \
      { \
         if (*num > static_cast<int>(val->size())) \
            *num = val->size(); \
         int count = 0; \
         for (it = val->begin(); it != val->end(); ++ it) \
         { \
            if (count >= *num) \
               break; \
            fds[count ++] = *it; \
         } \
      } \
   }

*/

template <class SOCKTYPE>
inline void set_result(set<SOCKTYPE>* val, int* num, SOCKTYPE* fds)
{
    if ( !val || !num || !fds )
        return;

    if (*num > int(val->size()))
        *num = int(val->size()); // will get 0 if val->empty()
    int count = 0;

    // This loop will run 0 times if val->empty()
    for (typename set<SOCKTYPE>::const_iterator it = val->begin(); it != val->end(); ++ it)
    {
        if (count >= *num)
            break;
        fds[count ++] = *it;
    }
}

int epoll_wait2(
   int eid, SRTSOCKET* readfds,
   int* rnum, SRTSOCKET* writefds,
   int* wnum,
   int64_t msTimeOut,
   SYSSOCKET* lrfds,
   int* lrnum,
   SYSSOCKET* lwfds,
   int* lwnum)
{
   // This API is an alternative format for epoll_wait, created for
   // compatability with other languages. Users need to pass in an array
   // for holding the returned sockets, with the maximum array length
   // stored in *rnum, etc., which will be updated with returned number
   // of sockets.

   set<SRTSOCKET> readset;
   set<SRTSOCKET> writeset;
   set<SYSSOCKET> lrset;
   set<SYSSOCKET> lwset;
   set<SRTSOCKET>* rval = NULL;
   set<SRTSOCKET>* wval = NULL;
   set<SYSSOCKET>* lrval = NULL;
   set<SYSSOCKET>* lwval = NULL;
   if ((readfds != NULL) && (rnum != NULL))
      rval = &readset;
   if ((writefds != NULL) && (wnum != NULL))
      wval = &writeset;
   if ((lrfds != NULL) && (lrnum != NULL))
      lrval = &lrset;
   if ((lwfds != NULL) && (lwnum != NULL))
      lwval = &lwset;

   int ret = CUDT::epoll_wait(eid, rval, wval, msTimeOut, lrval, lwval);
   if (ret > 0)
   {
      //set<SRTSOCKET>::const_iterator i;
      //SET_RESULT(rval, rnum, readfds, i);
      set_result(rval, rnum, readfds);
      //SET_RESULT(wval, wnum, writefds, i);
      set_result(wval, wnum, writefds);

      //set<SYSSOCKET>::const_iterator j;
      //SET_RESULT(lrval, lrnum, lrfds, j);
      set_result(lrval, lrnum, lrfds);
      //SET_RESULT(lwval, lwnum, lwfds, j);
      set_result(lwval, lwnum, lwfds);
   }
   return ret;
}

int epoll_release(int eid)
{
   return CUDT::epoll_release(eid);
}

ERRORINFO& getlasterror()
{
   return CUDT::getlasterror();
}

int getlasterror_code()
{
   return CUDT::getlasterror().getErrorCode();
}

const char* getlasterror_desc()
{
   return CUDT::getlasterror().getErrorMessage();
}

int getlasterror_errno()
{
   return CUDT::getlasterror().getErrno();
}

// Get error string of a given error code
const char* geterror_desc(int code, int err)
{
   // static CUDTException e; //>>Need something better than static here.
   // Yeah, of course. Here you are:
   CUDTException e (CodeMajor(code/1000), CodeMinor(code%1000), err);
   return(e.getErrorMessage());
}


SRT_ATR_DEPRECATED int perfmon(SRTSOCKET u, TRACEINFO* perf, bool clear)
{
   return CUDT::perfmon(u, perf, clear);
}

int bstats(SRTSOCKET u, TRACEBSTATS* perf, bool clear)
{
   return CUDT::bstats(u, perf, clear);
}

SRT_SOCKSTATUS getsockstate(SRTSOCKET u)
{
   return CUDT::getsockstate(u);
}

void setloglevel(logging::LogLevel::type ll)
{
    CGuard gg(srt_logger_config.mutex);
    srt_logger_config.max_level = ll;
}

void addlogfa(logging::LogFA fa)
{
    CGuard gg(srt_logger_config.mutex);
    srt_logger_config.enabled_fa.insert(fa);
}

void dellogfa(logging::LogFA fa)
{
    CGuard gg(srt_logger_config.mutex);
    srt_logger_config.enabled_fa.erase(fa);
}

void resetlogfa(set<logging::LogFA> fas)
{
    CGuard gg(srt_logger_config.mutex);
    set<int> enfas;
    copy(fas.begin(), fas.end(), std::inserter(enfas, enfas.begin()));
    srt_logger_config.enabled_fa = enfas;
}

void setlogstream(std::ostream& stream)
{
    CGuard gg(srt_logger_config.mutex);
    srt_logger_config.log_stream = &stream;
}

void setloghandler(void* opaque, SRT_LOG_HANDLER_FN* handler)
{
    CGuard gg(srt_logger_config.mutex);
    srt_logger_config.loghandler_opaque = opaque;
    srt_logger_config.loghandler_fn = handler;
}

void setlogflags(int flags)
{
    CGuard gg(srt_logger_config.mutex);
    srt_logger_config.flags = flags;
}

SRT_API bool setstreamid(SRTSOCKET u, const std::string& sid)
{
    return CUDT::setstreamid(u, sid);
}
SRT_API std::string getstreamid(SRTSOCKET u)
{
    return CUDT::getstreamid(u);
}

}  // namespace UDT
