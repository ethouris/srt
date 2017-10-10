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
****************************************************************************/

/****************************************************************************
written by
   Yunhong Gu, last updated 01/27/2011
modified by
   Haivision Systems Inc.
*****************************************************************************/

#ifndef WIN32
   #if __APPLE__
      #include "TargetConditionals.h"
   #endif
   #include <sys/socket.h>
   #include <sys/ioctl.h>
   #include <netdb.h>
   #include <arpa/inet.h>
   #include <unistd.h>
   #include <fcntl.h>
   #include <cstring>
   #include <cstdio>
   #include <cerrno>
#else
   #include <winsock2.h>
   #include <ws2tcpip.h>
#endif

#include <iostream>
#include <iomanip> // Logging 
#include <srt_compat.h>
#include <csignal>

#include "channel.h"
#include "packet.h"
#include "api.h" // SockaddrToString - possibly move it to somewhere else
#include "logging.h"
#include "netinet_any.h"

#ifdef WIN32
    typedef int socklen_t;
#endif

#ifndef WIN32
   #define NET_ERROR errno
#else
   #define NET_ERROR WSAGetLastError()
#endif

using namespace std;


extern logging::Logger mglog;

CChannel::CChannel():
m_iSocket(),
#ifdef SRT_ENABLE_IPOPTS
m_iIpTTL(-1),
m_iIpToS(-1),
#endif
m_iSndBufSize(65536),
m_iRcvBufSize(65536)
{
}

CChannel::~CChannel()
{
}

void CChannel::createSocket(int family)
{
    // construct an socket
    m_iSocket = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);

#ifdef WIN32
    int invalid = INVALID_SOCKET;
#else
    int invalid = -1;
#endif

    if (m_iSocket == invalid)
        throw CUDTException(MJ_SETUP, MN_NONE, NET_ERROR);

}

void CChannel::open(const sockaddr_any& addr)
{
    createSocket(addr.family());
    socklen_t namelen = addr.size();

    if (::bind(m_iSocket, &addr.sa, namelen) == -1)
        throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);

    m_BindAddr = addr;

    LOGC(mglog.Debug) << "CHANNEL: Bound to local address: " << SockaddrToString(m_BindAddr);

    setUDPSockOpt();
}

void CChannel::open(int family)
{
    createSocket(family);

    //sendto or WSASendTo will also automatically bind the socket
    addrinfo hints;
    addrinfo* res;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;

    int eai = ::getaddrinfo(NULL, "0", &hints, &res);
    if (eai != 0)
    {
        // Controversial a little bit because this function occasionally
        // doesn't use errno (here: NET_ERROR for portability), instead
        // it returns 0 if succeeded or an error code. This error code
        // is passed here then. A controversy is around the fact that
        // the receiver of this error has completely no ability to know
        // what this error code's domain is, and it definitely isn't
        // the same as for errno.
        throw CUDTException(MJ_SETUP, MN_NORES, eai);
    }

    if (::bind(m_iSocket, res->ai_addr, res->ai_addrlen) == -1)
        throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);

    m_BindAddr = sockaddr_any(res->ai_addr, res->ai_addrlen);
    ::freeaddrinfo(res);

    LOGC(mglog.Debug) << "CHANNEL: Bound to local address: " << SockaddrToString(m_BindAddr);

    setUDPSockOpt();
}

void CChannel::attach(int udpsock, const sockaddr_any& udpsocks_addr)
{
    // The getsockname() call is done before calling it and the
    // result is placed into udpsocks_addr.
    m_iSocket = udpsock;
    m_BindAddr = udpsocks_addr;
    setUDPSockOpt();
}

void CChannel::setUDPSockOpt()
{
   #if defined(BSD) || defined(OSX) || defined(TARGET_OS_IOS) || defined(TARGET_OS_TV)
      // BSD system will fail setsockopt if the requested buffer size exceeds system maximum value
      int maxsize = 64000;
      if (0 != ::setsockopt(m_iSocket, SOL_SOCKET, SO_RCVBUF, (char*)&m_iRcvBufSize, sizeof(int)))
         ::setsockopt(m_iSocket, SOL_SOCKET, SO_RCVBUF, (char*)&maxsize, sizeof(int));
      if (0 != ::setsockopt(m_iSocket, SOL_SOCKET, SO_SNDBUF, (char*)&m_iSndBufSize, sizeof(int)))
         ::setsockopt(m_iSocket, SOL_SOCKET, SO_SNDBUF, (char*)&maxsize, sizeof(int));
   #else
      // for other systems, if requested is greated than maximum, the maximum value will be automactally used
      if ((0 != ::setsockopt(m_iSocket, SOL_SOCKET, SO_RCVBUF, (char*)&m_iRcvBufSize, sizeof(int))) ||
          (0 != ::setsockopt(m_iSocket, SOL_SOCKET, SO_SNDBUF, (char*)&m_iSndBufSize, sizeof(int))))
         throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);
   #endif

#ifdef SRT_ENABLE_IPOPTS
      if ((-1 != m_iIpTTL)
      &&  (0 != ::setsockopt(m_iSocket, IPPROTO_IP, IP_TTL, (const char*)&m_iIpTTL, sizeof(m_iIpTTL))))
         throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);
         
      if ((-1 != m_iIpToS)
      &&  (0 != ::setsockopt(m_iSocket, IPPROTO_IP, IP_TOS, (const char*)&m_iIpToS, sizeof(m_iIpToS))))
         throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);
#endif

   timeval tv;
   tv.tv_sec = 0;
   #if defined (BSD) || defined (OSX) || defined(TARGET_OS_IOS) || defined(TARGET_OS_TV)
      // Known BSD bug as the day I wrote this code.
      // A small time out value will cause the socket to block forever.
      tv.tv_usec = 10000;
   #else
      tv.tv_usec = 100;
   #endif

   #ifdef UNIX
      // Set non-blocking I/O
      // UNIX does not support SO_RCVTIMEO
      int opts = ::fcntl(m_iSocket, F_GETFL);
      if (-1 == ::fcntl(m_iSocket, F_SETFL, opts | O_NONBLOCK))
         throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);
   #elif defined(WIN32)
      DWORD ot = 1; //milliseconds
      if (0 != ::setsockopt(m_iSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&ot, sizeof(DWORD)))
         throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);
   #else
      // Set receiving time-out value
      if (0 != ::setsockopt(m_iSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(timeval)))
         throw CUDTException(MJ_SETUP, MN_NORES, NET_ERROR);
   #endif
}

void CChannel::close() const
{
   #ifndef WIN32
      ::close(m_iSocket);
   #else
      ::closesocket(m_iSocket);
   #endif
}

int CChannel::getSndBufSize()
{
   socklen_t size = sizeof(socklen_t);
   ::getsockopt(m_iSocket, SOL_SOCKET, SO_SNDBUF, (char *)&m_iSndBufSize, &size);
   return m_iSndBufSize;
}

int CChannel::getRcvBufSize()
{
   socklen_t size = sizeof(socklen_t);
   ::getsockopt(m_iSocket, SOL_SOCKET, SO_RCVBUF, (char *)&m_iRcvBufSize, &size);
   return m_iRcvBufSize;
}

void CChannel::setSndBufSize(int size)
{
   m_iSndBufSize = size;
}

void CChannel::setRcvBufSize(int size)
{
   m_iRcvBufSize = size;
}

#ifdef SRT_ENABLE_IPOPTS
int CChannel::getIpTTL() const
{
   socklen_t size = sizeof(m_iIpTTL);
   ::getsockopt(m_iSocket, IPPROTO_IP, IP_TTL, (char *)&m_iIpTTL, &size);
   return m_iIpTTL;
}

int CChannel::getIpToS() const
{
   socklen_t size = sizeof(m_iIpToS);
   ::getsockopt(m_iSocket, IPPROTO_IP, IP_TOS, (char *)&m_iIpToS, &size);
   return m_iIpToS;
}

void CChannel::setIpTTL(int ttl)
{
   m_iIpTTL = ttl;
}

void CChannel::setIpToS(int tos)
{
   m_iIpToS = tos;
}

#endif

int CChannel::ioctlQuery(int type) const
{
#ifdef unix
    int value = 0;
    int res = ::ioctl(m_iSocket, type, &value);
    if ( res != -1 )
        return value;
#endif
    return -1;
}

int CChannel::sockoptQuery(int level, int option) const
{
#ifdef unix
    int value = 0;
    socklen_t len = sizeof (int);
    int res = ::getsockopt(m_iSocket, level, option, &value, &len);
    if ( res != -1 )
        return value;
#endif
    return -1;
}

void CChannel::getSockAddr(ref_t<sockaddr_any> addr) const
{
    // The getsockname function requires only to have enough target
    // space to copy the socket name, it doesn't have to be corelated
    // with the address family. So the maximum space for any name,
    // regardless of the family, does the job.
    socklen_t namelen = sizeof(addr.get());
    ::getsockname(m_iSocket, &addr.get(), &namelen);
}

void CChannel::getPeerAddr(ref_t<sockaddr_any> addr) const
{
    socklen_t namelen = sizeof(addr.get());
    ::getpeername(m_iSocket, &addr.get(), &namelen);
}


int CChannel::sendto(const sockaddr_any& addr, CPacket& packet) const
{
#if ENABLE_LOGGING
    std::ostringstream spec;

    if (packet.isControl())
    {
        spec << " CONTROL size=" << packet.getLength()
             << " cmd=" << MessageTypeStr(packet.getType(), packet.getExtendedType())
             << " arg=" << packet.getHeader()[CPacket::PH_MSGNO];
    }
    else
    {
        spec << " DATA size=" << packet.getLength()
             << " seq=" << packet.getSeqNo();
        if (packet.getRexmitFlag())
            spec << " [REXMIT]";
    }

    LOGC(mglog.Debug) << "CChannel::sendto: SENDING NOW DST=" << SockaddrToString(addr)
        << " target=%" << packet.m_iID
        << spec.str();
#endif

   // convert control information into network order
   // XXX USE HtoNLA!
   if (packet.isControl())
      for (int i = 0, n = packet.getLength() / 4; i < n; ++ i)
         *((uint32_t *)packet.m_pcData + i) = htonl(*((uint32_t *)packet.m_pcData + i));

   // convert packet header into network order
   //for (int j = 0; j < 4; ++ j)
   //   packet.m_nHeader[j] = htonl(packet.m_nHeader[j]);
   uint32_t* p = packet.m_nHeader;
   for (int j = 0; j < 4; ++ j)
   {
      *p = htonl(*p);
      ++ p;
   }

   #ifndef WIN32
      msghdr mh;
      mh.msg_name = (sockaddr*)&addr;
      mh.msg_namelen = addr.size();
      mh.msg_iov = (iovec*)packet.m_PacketVector;
      mh.msg_iovlen = 2;
      mh.msg_control = NULL;
      mh.msg_controllen = 0;
      mh.msg_flags = 0;

      int res = ::sendmsg(m_iSocket, &mh, 0);
   #else
      DWORD size = CPacket::HDR_SIZE + packet.getLength();
      int addrsize = m_iSockAddrSize;
      int res = ::WSASendTo(m_iSocket, (LPWSABUF)packet.m_PacketVector, 2, &size, 0, addr, addrsize, NULL, NULL);
      res = (0 == res) ? size : -1;
   #endif

   // convert back into local host order
   //for (int k = 0; k < 4; ++ k)
   //   packet.m_nHeader[k] = ntohl(packet.m_nHeader[k]);
   p = packet.m_nHeader;
   for (int k = 0; k < 4; ++ k)
   {
      *p = ntohl(*p);
       ++ p;
   }

   if (packet.isControl())
   {
      for (int l = 0, n = packet.getLength() / 4; l < n; ++ l)
         *((uint32_t *)packet.m_pcData + l) = ntohl(*((uint32_t *)packet.m_pcData + l));
   }

   return res;
}

EReadStatus CChannel::recvfrom(ref_t<sockaddr_any> r_addr, CPacket& packet) const
{
    EReadStatus status = RST_OK;
    sockaddr* addr = &r_addr.get();

#ifndef WIN32
    msghdr mh;   
    mh.msg_name = addr;
    mh.msg_namelen = r_addr.get().size();
    mh.msg_iov = packet.m_PacketVector;
    mh.msg_iovlen = 2;
    mh.msg_control = NULL;
    mh.msg_controllen = 0;
    mh.msg_flags = 0;

#ifdef UNIX
    fd_set set;
    timeval tv;
    FD_ZERO(&set);
    FD_SET(m_iSocket, &set);
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    ::select(m_iSocket+1, &set, NULL, &set, &tv);
#endif

    int res = ::recvmsg(m_iSocket, &mh, 0);
    int msg_flags = mh.msg_flags;
#else
    // XXX This procedure uses the WSARecvFrom function that just reads
    // into one buffer. On Windows, the equivalent for recvmsg, WSARecvMsg
    // uses the equivalent of msghdr - WSAMSG, which has different field
    // names and also uses the equivalet of iovec - WSABUF, which has different
    // field names and layout. It is important that this code be translated
    // to the "proper" solution, however this requires that CPacket::m_PacketVector
    // also uses the "platform independent" (or, better, platform-suitable) type
    // which can be appropriate for the appropriate system function, not just iovec.
    //
    // For the time being, the msg_flags variable is defined in both cases
    // so that it can be checked independently, however it won't have any other
    // value one Windows than 0, unless this procedure below is rewritten
    // to use WSARecvMsg().

    DWORD size = CPacket::HDR_SIZE + packet.getLength();
    DWORD flag = 0;
    int addrsize = m_iSockAddrSize;

    int res = ::WSARecvFrom(m_iSocket, (LPWSABUF)packet.m_PacketVector, 2, &size, &flag, addr, &addrsize, NULL, NULL);
    res = (0 == res) ? size : -1;
    int msg_flags = 0;
#endif

    // Note that there are exactly four groups of possible errors
    // reported by recvmsg():

    // 1. Temporary error, can't get the data, but you can try again.
    // Codes: EAGAIN/EWOULDBLOCK, EINTR
    // Return: RST_AGAIN.
    //
    // 2. Problems that should never happen due to unused configurations.
    // Codes: ECONNREFUSED, ENOTCONN
    // Return: RST_ERROR, just formally treat this as IPE.
    //
    // 3. Unexpected runtime errors:
    // Codes: EINVAL, EFAULT, ENOMEM, ENOTSOCK
    // Return: RST_ERROR. Except ENOMEM, this can only be an IPE. ENOMEM
    // should make the program stop as lacking memory will kill the program anyway soon.
    //
    // 4. Expected socket closed in the meantime by another thread.
    // Codes: EBADF
    // Return: RST_ERROR. This will simply make the worker thread exit, which is
    // expected to happen after CChannel::close() is called by another thread.

    if ( res == -1 )
    {
        int err = NET_ERROR;
        if ( err == EAGAIN || err == EINTR ) // For EAGAIN, this isn't an error, just a useless call.
        {
            status = RST_AGAIN;
        }
        else
        {
            LOGC(mglog.Debug) << CONID() << "(sys)recvmsg: " << SysStrError(err) << " [" << err << "]";
            status = RST_ERROR;
        }

        goto Return_error;
    }

    // Sanity check for a case when it didn't fill in even the header
    if ( size_t(res) < CPacket::HDR_SIZE )
    {
        status = RST_AGAIN;
        LOGC(mglog.Debug) << CONID() << "POSSIBLE ATTACK: received too short packet with " << res << " bytes";
        goto Return_error;
    }

    // Fix for an issue found at Tenecent.
    // By some not well known reason, Linux kernel happens to copy only 20 bytes of
    // UDP payload and set the MSG_TRUNC flag, whereas pcap shows that full UDP
    // packet arrived at the network device, and the free space in a buffer is
    // always the same and >1332 bytes. Nice of it to set this flag, though.
    //
    // In normal conditions, no flags should be set. This shouldn't use any
    // other flags, but OTOH this situation also theoretically shouldn't happen
    // and it does. As a safe precaution, simply treat any flag set on the
    // message as "some problem".
    //
    // As a response for this situation, fake that you received no package. This will be
    // then a "fake drop", which will result in reXmission. This isn't even much of a fake
    // because the packet is partially lost and this loss is irrecoverable.

    if ( msg_flags != 0 )
    {
        LOGC(mglog.Debug) << CONID() << "NET ERROR: packet size=" << res
            << " msg_flags=0x" << hex << msg_flags << ", possibly MSG_TRUNC (0x" << hex << int(MSG_TRUNC) << ")";
        status = RST_AGAIN;
        goto Return_error;
    }

    packet.setLength(res - CPacket::HDR_SIZE);

    // convert back into local host order
    // XXX use NtoHLA().
    //for (int i = 0; i < 4; ++ i)
    //   packet.m_nHeader[i] = ntohl(packet.m_nHeader[i]);
    {
        uint32_t* p = packet.m_nHeader;
        for (size_t i = 0; i < CPacket::PH_SIZE; ++ i)
        {
            *p = ntohl(*p);
            ++ p;
        }
    }

    if (packet.isControl())
    {
        for (size_t j = 0, n = packet.getLength() / sizeof (uint32_t); j < n; ++ j)
            *((uint32_t *)packet.m_pcData + j) = ntohl(*((uint32_t *)packet.m_pcData + j));
    }

    return RST_OK;

Return_error:
    packet.setLength(-1);
    return status;
}
