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
   Yunhong Gu, last updated 02/28/2012
modified by
   Haivision Systems Inc.
*****************************************************************************/


#ifndef __UDT_CORE_H__
#define __UDT_CORE_H__

#include <deque>
#include <sstream>

#include "srt.h"
#include "common.h"
#include "list.h"
#include "buffer.h"
#include "window.h"
#include "packet.h"
#include "channel.h"
#include "cache.h"
#include "queue.h"
#include "handshake.h"
#include "smoother.h"
#include "utilities.h"

#include <haicrypt.h>

extern logging::Logger
    glog,
    blog,
    mglog,
    dlog,
    tslog,
    rxlog;


// XXX Utility function - to be moved to utilities.h?
template <class T>
inline T CountIIR(T base, T newval, double factor)
{
    if ( base == 0.0 )
        return newval;

    T diff = newval - base;
    return base+T(diff*factor);
}

// XXX Probably a better rework for that can be done - this can be
// turned into a serializable structure, just like it's for CHandShake.
enum AckDataItem
{
    ACKD_RCVLASTACK = 0,
    ACKD_RTT = 1,
    ACKD_RTTVAR = 2,
    ACKD_BUFFERLEFT = 3,
    ACKD_TOTAL_SIZE_SMALL = 4,

    // Extra fields existing in UDT (not always sent)

    ACKD_RCVSPEED = 4,   // length would be 16
    ACKD_BANDWIDTH = 5,
    ACKD_TOTAL_SIZE_UDTBASE = 6, // length = 24
    // Extra stats for SRT

    ACKD_RCVRATE = 6,
    ACKD_TOTAL_SIZE_VER101 = 7, // length = 28
    ACKD_XMRATE = 7, // XXX This is a weird compat stuff. Version 1.1.3 defines it as ACKD_BANDWIDTH*m_iMaxSRTPayloadSize when set. Never got.
                     // XXX NOTE: field number 7 may be used for something in future, need to confirm destruction of all !compat 1.0.2 version

    ACKD_TOTAL_SIZE_VER102 = 8, // 32
// FEATURE BLOCKED. Probably not to be restored.
//  ACKD_ACKBITMAP = 8,
    ACKD_TOTAL_SIZE = ACKD_TOTAL_SIZE_VER102 // length = 32 (or more)
};
const size_t ACKD_FIELD_SIZE = sizeof(int32_t);

// For HSv4 legacy handshake
#define SRT_MAX_HSRETRY     10          /* Maximum SRT handshake retry */

enum SeqPairItems
{
    SEQ_BEGIN = 0, SEQ_END = 1, SEQ_SIZE = 2
};

// Extended SRT Congestion control class - only an incomplete definition required
class CCryptoControl;
class CUDTUnited;
class CUDTSocket;

class CUDTSocket;

class CUDTGroup
{
    friend class CUDTUnited;

public:
    enum GroupState
    {
        GST_PENDING,  // The socket is created correctly, but not yet ready for getting data.
        GST_IDLE,     // The socket should be activated at the next operation immediately.
        GST_RUNNING,  // The socket was already activated and is in use
        GST_BROKEN    // The last operation broke the socket, it should be closed.
    };

    struct SocketData
    {
        SRTSOCKET id;
        CUDTSocket* ps;
        SRT_SOCKSTATUS laststatus;
        GroupState sndstate;
        GroupState rcvstate;
        sockaddr_any agent;
        sockaddr_any peer;
        bool ready_read;
        bool ready_write;
        bool ready_error;
    };

    struct ConfigItem
    {
        SRT_SOCKOPT so;
        std::vector<unsigned char> value;

        template<class T> bool get(T& refr)
        {
            if (sizeof(T) > value.size())
                return false;
            refr = *(T*)&value[0];
        }

        ConfigItem(SRT_SOCKOPT o, const void* val, int size): so(o)
        {
            value.resize(size);
            unsigned char* begin = (unsigned char*)val;
            std::copy(begin, begin+size, value.begin());
        }
    };

    struct Payload
    {
        SRTSOCKET id;
        int result;
        std::vector<char> data;
        SRT_MSGCTRL ctrl;
    };

    typedef std::list<SocketData> group_t;
    typedef group_t::iterator gli_t;
    CUDTGroup();
    ~CUDTGroup();

    static SocketData prepareData(CUDTSocket* s);

    gli_t add(SocketData data);

    struct HaveID
    {
        SRTSOCKET id;
        HaveID(SRTSOCKET sid): id(sid) {}
        bool operator()(const SocketData& s) { return s.id == id; }
    };

    gli_t find(SRTSOCKET id)
    {
        CGuard g(m_GroupLock);
        gli_t f = std::find_if(m_Group.begin(), m_Group.end(), HaveID(id));
        if (f == m_Group.end())
        {
            return gli_NULL();
        }
        return f;
    }

    // REMEMBER: the group spec should be taken from the socket
    // (set m_IncludedGroup to NULL and m_IncludedIter to grp->gli_NULL())
    // PRIOR TO calling this function.
    bool remove(SRTSOCKET id)
    {
        CGuard g(m_GroupLock);
        gli_t f = std::find_if(m_Group.begin(), m_Group.end(), HaveID(id));
        if (f != m_Group.end())
        {
            m_Group.erase(f);
        }

        return false;
    }

    bool empty()
    {
        CGuard g(m_GroupLock);
        return m_Group.empty();
    }

    void resetStateOn(CUDTSocket* sock);

    void signalReadAvail(CUDTSocket* readysock);

    static gli_t gli_NULL() { return s_NoGroup.end(); }

    int send(const char* buf, int len, ref_t<SRT_MSGCTRL> mc);
    int recv(char* buf, int len, ref_t<SRT_MSGCTRL> mc);

    void close();

    void setOpt(SRT_SOCKOPT optname, const void* optval, int optlen);
    void getOpt(SRT_SOCKOPT optName, void* optval, ref_t<int> optlen);

private:

    class CUDTUnited* m_pGlobal;
    pthread_mutex_t m_GroupLock;

    SRTSOCKET m_GroupID;
    SRTSOCKET m_PeerGroupID;
    std::list<SocketData> m_Group;
    static std::list<SocketData> s_NoGroup; // This is to have a predictable "null iterator".
    bool m_selfManaged;
    SRT_GROUP_TYPE m_type;
    CUDTSocket* m_listener; // A "group" can only have one listener.
    std::set<int> m_sPollID;                     // set of epoll ID to trigger
    int m_iMaxPayloadSize;
    bool m_bSynRecving;
    pthread_t m_GroupReaderThread;
    std::queue<Payload> m_PayloadQ;
    pthread_cond_t m_PayloadReadAvail;
    bool m_bOpened;                    // Set to true on a first use

    // There's no simple way of transforming config
    // items that are predicted to be used on socket.
    // Use some options for yourself, store the others
    // for setting later on a socket.
    std::vector<ConfigItem> m_config;

    void readerThread();
    static void* readerThread_fwd(void* arg)
    {
        CUDTGroup* self = (CUDTGroup*)arg;
        self->readerThread();
        return 0;
    }

    pthread_cond_t m_GroupReadAvail;
    volatile CUDTSocket* m_ReadyRead;
    volatile int32_t m_iRcvDeliveredSeqNo; // Seq of the payload last delivered
    volatile int32_t m_iRcvContiguousSeqNo; // Seq of the freshest payload stored in the buffer with no loss-gap
    //volatile std::set<SRTSOCKET> m_Failures;

public:

    // Property accessors
    SRTU_PROPERTY_RW_CHAIN(CUDTGroup, SRTSOCKET, id, m_GroupID);
    SRTU_PROPERTY_RW_CHAIN(CUDTGroup, SRTSOCKET, peerid, m_PeerGroupID);
    SRTU_PROPERTY_RW_CHAIN(CUDTGroup, bool, managed, m_selfManaged);
    SRTU_PROPERTY_RW_CHAIN(CUDTGroup, SRT_GROUP_TYPE, type, m_type);
};


// XXX REFACTOR: The 'CUDT' class is to be merged with 'CUDTSocket'.
// There's no reason for separating them, there's no case of having them
// anyhow managed separately. After this is done, with a small help with
// separating the internal abnormal path management (exceptions) from the
// API (return values), through CUDTUnited, this class may become in future
// an officially exposed C++ API.
class CUDT
{
    friend class CUDTSocket;
    friend class CUDTGroup;
    friend class CUDTUnited;
    friend class CCC;
    friend struct CUDTComp;
    friend class CCache<CInfoBlock>;
    friend class CRendezvousQueue;
    friend class CSndQueue;
    friend class CRcvQueue;
    friend class CSndUList;
    friend class CRcvUList;

private: // constructor and desctructor

    void construct();
    void clearData();
    CUDT(CUDTSocket* parent);
    CUDT(CUDTSocket* parent, const CUDT& ancestor);
    const CUDT& operator=(const CUDT&) {return *this;} // = delete ?
    ~CUDT();

public: //API

    static int startup();
    static int cleanup();
    static SRTSOCKET socket();
    static SRTSOCKET createGroup(SRT_GROUP_TYPE);
    static int addSocketToGroup(SRTSOCKET socket, SRTSOCKET group);
    static int removeSocketFromGroup(SRTSOCKET socket);
    static SRTSOCKET getGroupOfSocket(SRTSOCKET socket);
    static int bind(SRTSOCKET u, const sockaddr* name, int namelen);
    static int bind(SRTSOCKET u, int udpsock);
    static int listen(SRTSOCKET u, int backlog);
    static SRTSOCKET accept(SRTSOCKET u, sockaddr* addr, int* addrlen);
    static int connect(SRTSOCKET u, const sockaddr* name, int namelen, int32_t forced_isn);
    static int connect(SRTSOCKET u, const sockaddr* name, int namelen, const sockaddr* tname, int tnamelen);
    static int close(SRTSOCKET u);
    static int getpeername(SRTSOCKET u, sockaddr* name, int* namelen);
    static int getsockname(SRTSOCKET u, sockaddr* name, int* namelen);
    static int getsockopt(SRTSOCKET u, int level, SRT_SOCKOPT optname, void* optval, int* optlen);
    static int setsockopt(SRTSOCKET u, int level, SRT_SOCKOPT optname, const void* optval, int optlen);
    static int send(SRTSOCKET u, const char* buf, int len);
    static int recv(SRTSOCKET u, char* buf, int len);
    static int sendmsg(SRTSOCKET u, const char* buf, int len, int ttl = -1, bool inorder = false, uint64_t srctime = 0LL);
    static int recvmsg(SRTSOCKET u, char* buf, int len, uint64_t& srctime);
    static int sendmsg2(SRTSOCKET u, const char* buf, int len, ref_t<SRT_MSGCTRL> mctrl);
    static int recvmsg2(SRTSOCKET u, char* buf, int len, ref_t<SRT_MSGCTRL> mctrl);
    static int64_t sendfile(SRTSOCKET u, std::fstream& ifs, int64_t& offset, int64_t size, int block = SRT_DEFAULT_SENDFILE_BLOCK);
    static int64_t recvfile(SRTSOCKET u, std::fstream& ofs, int64_t& offset, int64_t size, int block = SRT_DEFAULT_RECVFILE_BLOCK);
    static int select(int nfds, ud_set* readfds, ud_set* writefds, ud_set* exceptfds, const timeval* timeout);
    static int selectEx(const std::vector<SRTSOCKET>& fds, std::vector<SRTSOCKET>* readfds, std::vector<SRTSOCKET>* writefds, std::vector<SRTSOCKET>* exceptfds, int64_t msTimeOut);
    static int epoll_create();
    static int epoll_add_usock(const int eid, const SRTSOCKET u, const int* events = NULL);
    static int epoll_add_ssock(const int eid, const SYSSOCKET s, const int* events = NULL);
    static int epoll_remove_usock(const int eid, const SRTSOCKET u);
    static int epoll_remove_ssock(const int eid, const SYSSOCKET s);
    static int epoll_update_usock(const int eid, const SRTSOCKET u, const int* events = NULL);
    static int epoll_update_ssock(const int eid, const SYSSOCKET s, const int* events = NULL);
    static int epoll_wait(const int eid, std::set<SRTSOCKET>* readfds, std::set<SRTSOCKET>* writefds, int64_t msTimeOut, std::set<SYSSOCKET>* lrfds = NULL, std::set<SYSSOCKET>* wrfds = NULL);
    static int epoll_release(const int eid);
    static CUDTException& getlasterror();
    static int perfmon(SRTSOCKET u, CPerfMon* perf, bool clear = true);
    static int bstats(SRTSOCKET u, CBytePerfMon* perf, bool clear = true);
    static SRT_SOCKSTATUS getsockstate(SRTSOCKET u);
    static bool setstreamid(SRTSOCKET u, const std::string& sid);
    static std::string getstreamid(SRTSOCKET u);
    static int getsndbuffer(SRTSOCKET u, size_t* blocks, size_t* bytes);
    static int setError(const CUDTException& e);
    static int setError(CodeMajor mj, CodeMinor mn, int syserr);


public: // internal API
    static const SRTSOCKET INVALID_SOCK = -1;         // invalid socket descriptor
    static const int ERROR = -1;                      // socket api error returned value

    static const int HS_VERSION_UDT4 = 4;
    static const int HS_VERSION_SRT1 = 5;

    // Parameters
    //
    // Note: use notation with X*1000*1000* ... instead of million zeros in a row.
    // In C++17 there is a possible notation of 5'000'000 for convenience, but that's
    // something only for a far future.
    static const int COMM_RESPONSE_TIMEOUT_US = 5*1000*1000; // 5 seconds
    static const int COMM_RESPONSE_MAX_EXP = 16;
    static const int SRT_TLPKTDROP_MINTHRESHOLD_MS = 1000;
    static const uint64_t COMM_KEEPALIVE_PERIOD_US = 1*1000*1000;
    static const int32_t COMM_SYN_INTERVAL_US = 10*1000;

    int handshakeVersion()
    {
        return m_ConnRes.m_iVersion;
    }

    std::string CONID() const
    {
#if ENABLE_LOGGING
        std::ostringstream os;
        os << "%" << m_SocketID << ":";
        return os.str();
#else
        return "";
#endif
    }

    SRTSOCKET socketID() { return m_SocketID; }

    static CUDT* getUDTHandle(SRTSOCKET u);
    static std::vector<SRTSOCKET> existingSockets();

    void addressAndSend(CPacket& pkt);
    void sendSrtMsg(int cmd, uint32_t *srtdata_in = NULL, int srtlen_in = 0);

    bool isTsbPd() { return m_bOPT_TsbPd; }
    int RTT() { return m_iRTT; }
    int32_t sndSeqNo() { return m_iSndCurrSeqNo; }

    void overrideSndSeqNo(int32_t seq, bool initial = true)
    {
        // This function is predicted to be called from the socket
        // group managmenet functions to synchronize the sequnece in
        // all sockes in the redundancy group. THIS sequence given
        // here is the sequence TO BE STAMPED AT THE EXACTLY NEXT
        // sent payload. Therefore, screw up the ISN to exactly this
        // value, and the send sequence to the value one less - because
        // the m_iSndCurrSeqNo is increased by one immediately before
        // stamping it to the packet.

        // This function can only be called:
        // - from the operation on an idle socket in the socket group
        // - IMMEDIATELY after connection established and BEFORE the first payload
        // - The corresponding socket at the peer side must be also
        //   in this idle state!
        if (initial)
            m_iISN = seq;
        m_iSndCurrSeqNo = CSeqNo::decseq(seq);
    }

    int32_t rcvSeqNo() { return m_iRcvCurrSeqNo; }
    int flowWindowSize() { return m_iFlowWindowSize; }
    int32_t deliveryRate() { return m_iDeliveryRate; }
    int bandwidth() { return m_iBandwidth; }
    int64_t maxBandwidth() { return m_llMaxBW; }
    int MSS() { return m_iMSS; }
    size_t maxPayloadSize() { return m_iMaxSRTPayloadSize; }
    size_t OPT_PayloadSize() { return m_zOPT_ExpPayloadSize; }
    uint64_t minNAKInterval() { return m_ullMinNakInt_tk; }
    int32_t ISN() { return m_iISN; }

    // XXX See CUDT::tsbpd() to see how to implement it. This should
    // do the same as TLPKTDROP feature when skipping packets that are agreed
    // to be lost. Note that this is predicted to be called with TSBPD off.
    // This is to be exposed for the application so that it can require this
    // sequence to be skipped, if that packet has been otherwise arrived through
    // a different channel.
    void skipIncoming(int32_t seq);

    void ConnectSignal(ETransmissionEvent tev, EventSlot sl);
    void DisconnectSignal(ETransmissionEvent tev);

private:
    /// initialize a UDT entity and bind to a local address.

    void open();

    /// Start listening to any connection request.

    void setListenState();

    /// Connect to a UDT entity listening at address "peer".
    /// @param peer [in] The address of the listening UDT entity.

    void startConnect(const sockaddr_any& peer, int32_t forced_isn);

    /// Process the response handshake packet. Failure reasons can be:
    /// * Socket is not in connecting state
    /// * Response @a pkt is not a handshake control message
    /// * Rendezvous socket has once processed a regular handshake
    /// @param pkt [in] handshake packet.
    /// @retval 0 Connection successful
    /// @retval 1 Connection in progress (m_ConnReq turned into RESPONSE)
    /// @retval -1 Connection failed

    EConnectStatus processConnectResponse(const CPacket& pkt, CUDTException* eout, EConnectMethod synchro) ATR_NOEXCEPT;

    // This function works in case of HSv5 rendezvous. It changes the state
    // according to the present state and received message type, as well as the
    // INITIATOR/RESPONDER side resolved through cookieContest().
    // The resulting data are:
    // - rsptype: handshake message type that should be sent back to the peer (nothing if URQ_DONE)
    // - needs_extension: the HSREQ/KMREQ or HSRSP/KMRSP extensions should be attached to the handshake message.
    // - RETURNED VALUE: if true, it means a URQ_CONCLUSION message was received with HSRSP/KMRSP extensions and needs HSRSP/KMRSP.
    bool rendezvousSwitchState(ref_t<UDTRequestType> rsptype, ref_t<bool> needs_extension);
    void cookieContest();
    EConnectStatus processRendezvous(ref_t<CPacket> reqpkt, const CPacket &response, const sockaddr_any& serv_addr, bool synchro);
    bool prepareConnectionObjects(const CHandShake &hs, HandshakeSide hsd, CUDTException *eout);
    EConnectStatus postConnect(const CPacket& response, bool rendezvous, CUDTException* eout, bool synchro);
    void applyResponseSettings();
    EConnectStatus processAsyncConnectResponse(const CPacket& pkt) ATR_NOEXCEPT;
    bool processAsyncConnectRequest(EConnectStatus cst, const CPacket& response, const sockaddr_any& serv_addr);


    size_t fillSrtHandshake_HSREQ(uint32_t* srtdata, size_t srtlen, int hs_version);
    size_t fillSrtHandshake_HSRSP(uint32_t* srtdata, size_t srtlen, int hs_version);
    size_t fillSrtHandshake(uint32_t* srtdata, size_t srtlen, int msgtype, int hs_version);

    bool createSrtHandshake(ref_t<CPacket> reqpkt, ref_t<CHandShake> hs,
            int srths_cmd, int srtkm_cmd, const uint32_t* data, size_t datalen);

    size_t prepareSrtHsMsg(int cmd, uint32_t* srtdata, size_t size);

    bool processSrtMsg(const CPacket *ctrlpkt);
    int processSrtMsg_HSREQ(const uint32_t* srtdata, size_t len, uint32_t ts, int hsv);
    int processSrtMsg_HSRSP(const uint32_t* srtdata, size_t len, uint32_t ts, int hsv);
    bool interpretSrtHandshake(const CHandShake& hs, const CPacket& hspkt, uint32_t* out_data, size_t* out_len);

    static CUDTGroup& newGroup(int); // defined EXCEPTIONALLY in api.cpp for convenience reasons
    // Note: This is an "interpret" function, which should treat the tp as
    // "possibly group type" that might be out of the existing values.
    bool interpretGroup(SRTSOCKET grp, SRT_GROUP_TYPE tp);
    SRTSOCKET makeMePeerOf(SRTSOCKET peergroup, SRT_GROUP_TYPE tp);

    void updateAfterSrtHandshake(int srt_cmd, int hsv);

    void updateSrtRcvSettings();
    void updateSrtSndSettings();

    void checkNeedDrop(ref_t<bool> bCongestion);

    /// Connect to a UDT entity listening at address "peer", which has sent "hs" request.
    /// @param peer [in] The address of the listening UDT entity.
    /// @param hs [in/out] The handshake information sent by the peer side (in), negotiated value (out).

    void acceptAndRespond(const sockaddr_any& peer, CHandShake* hs, const CPacket& hspkt);

    /// Close the opened UDT entity.

    void close();

    /// Request UDT to send out a data block "data" with size of "len".
    /// @param data [in] The address of the application data to be sent.
    /// @param len [in] The size of the data block.
    /// @return Actual size of data sent.

    int send(const char* data, int len)
    {
        return sendmsg(data, len, -1, false, 0);
    }

    /// Request UDT to receive data to a memory block "data" with size of "len".
    /// @param data [out] data received.
    /// @param len [in] The desired size of data to be received.
    /// @return Actual size of data received.

    int recv(char* data, int len);

    /// send a message of a memory block "data" with size of "len".
    /// @param data [out] data received.
    /// @param len [in] The desired size of data to be received.
    /// @param ttl [in] the time-to-live of the message.
    /// @param inorder [in] if the message should be delivered in order.
    /// @param srctime [in] Time when the data were ready to send.
    /// @return Actual size of data sent.

    int sendmsg(const char* data, int len, int ttl, bool inorder, uint64_t srctime);
    /// Receive a message to buffer "data".
    /// @param data [out] data received.
    /// @param len [in] size of the buffer.
    /// @return Actual size of data received.

    int sendmsg2(const char* data, int len, ref_t<SRT_MSGCTRL> m);

    int recvmsg(char* data, int len, uint64_t& srctime);
    int recvmsg2(char* data, int len, ref_t<SRT_MSGCTRL> m);
    int receiveMessage(char* data, int len, ref_t<SRT_MSGCTRL> m);
    int receiveBuffer(char* data, int len);

    /// Request UDT to send out a file described as "fd", starting from "offset", with size of "size".
    /// @param ifs [in] The input file stream.
    /// @param offset [in, out] From where to read and send data; output is the new offset when the call returns.
    /// @param size [in] How many data to be sent.
    /// @param block [in] size of block per read from disk
    /// @return Actual size of data sent.

    int64_t sendfile(std::fstream& ifs, int64_t& offset, int64_t size, int block = 366000);

    /// Request UDT to receive data into a file described as "fd", starting from "offset", with expected size of "size".
    /// @param ofs [out] The output file stream.
    /// @param offset [in, out] From where to write data; output is the new offset when the call returns.
    /// @param size [in] How many data to be received.
    /// @param block [in] size of block per write to disk
    /// @return Actual size of data received.

    int64_t recvfile(std::fstream& ofs, int64_t& offset, int64_t size, int block = 7320000);

    /// Configure UDT options.
    /// @param optName [in] The enum name of a UDT option.
    /// @param optval [in] The value to be set.
    /// @param optlen [in] size of "optval".

    void setOpt(SRT_SOCKOPT optName, const void* optval, int optlen);

    /// Read UDT options.
    /// @param optName [in] The enum name of a UDT option.
    /// @param optval [in] The value to be returned.
    /// @param optlen [out] size of "optval".

    void getOpt(SRT_SOCKOPT optName, void* optval, ref_t<int> optlen);

    /// read the performance data since last sample() call.
    /// @param perf [in, out] pointer to a CPerfMon structure to record the performance data.
    /// @param clear [in] flag to decide if the local performance trace should be cleared.

    void sample(CPerfMon* perf, bool clear = true);

    // XXX please document
    void bstats(CBytePerfMon* perf, bool clear = true);

    /// Mark sequence contained in the given packet as not lost. This
    /// removes the loss record from both current receiver loss list and
    /// the receiver fresh loss list.
    void unlose(const CPacket& oldpacket);
    void unlose(int32_t from, int32_t to);

    void considerLegacySrtHandshake(uint64_t timebase);
    void checkSndTimers(Whether2RegenKm regen = DONT_REGEN_KM);
    void handshakeDone()
    {
        m_iSndHsRetryCnt = 0;
    }

    int64_t withOverhead(int64_t basebw)
    {
        return (basebw * (100 + m_iOverheadBW))/100;
    }

    static double Bps2Mbps(int64_t basebw)
    {
        return double(basebw) * 8.0/1000000.0;
    }

    bool stillConnected()
    {
        // Still connected is when:
        // - no "broken" condition appeared (security, protocol error, response timeout)
        return !m_bBroken
            // - still connected (no one called srt_close())
            && m_bConnected
            // - isn't currently closing (srt_close() called, response timeout, shutdown)
            && !m_bClosing;
    }

    int sndSpaceLeft()
    {
        return sndBuffersLeft() * m_iMaxSRTPayloadSize;
    }

    int sndBuffersLeft()
    {
        return m_iSndBufSize - m_pSndBuffer->getCurrBufSize();
    }


    // TSBPD thread main function.
    static void* tsbpd(void* param);

    static CUDTUnited s_UDTUnited;               // UDT global management base

private: // Identification

    CUDTSocket* const m_parent; // temporary, until the CUDTSocket class is merged with CUDT

    SRTSOCKET m_SocketID;                        // UDT socket number
    SRTSOCKET m_PeerID;                          // peer id, for multiplexer

    int m_iMaxSRTPayloadSize;                 // Maximum/regular payload size, in bytes
    size_t m_zOPT_ExpPayloadSize;                    // Expected average payload size (user option)

    // Options
    int m_iMSS;                                  // Maximum Segment Size, in bytes
    bool m_bSynSending;                          // Sending syncronization mode
    bool m_bSynRecving;                          // Receiving syncronization mode
    int m_iFlightFlagSize;                       // Maximum number of packets in flight from the peer side
    int m_iSndBufSize;                           // Maximum UDT sender buffer size
    int m_iRcvBufSize;                           // Maximum UDT receiver buffer size
    linger m_Linger;                             // Linger information on close
    int m_iUDPSndBufSize;                        // UDP sending buffer size
    int m_iUDPRcvBufSize;                        // UDP receiving buffer size
    //int m_iIPversion;                            // IP version
    bool m_bRendezvous;                          // Rendezvous connection mode
#ifdef SRT_ENABLE_CONNTIMEO
    int m_iConnTimeOut;                          // connect timeout in milliseconds
#endif
    int m_iSndTimeOut;                           // sending timeout in milliseconds
    int m_iRcvTimeOut;                           // receiving timeout in milliseconds
    bool m_bReuseAddr;                           // reuse an exiting port or not, for UDP multiplexer
    int64_t m_llMaxBW;                           // maximum data transfer rate (threshold)
#ifdef SRT_ENABLE_IPOPTS
    int m_iIpTTL;
    int m_iIpToS;
#endif
    // These fields keep the options for encryption
    // (SRTO_PASSPHRASE, SRTO_PBKEYLEN). Crypto object is
    // created later and takes values from these.
    HaiCrypt_Secret m_CryptoSecret;
    int m_iSndCryptoKeyLen;

    // XXX Consider removing them. The m_bDataSender may stay here
    // in order to maintain the HS side selection in HSv4.
    bool m_bDataSender;
    bool m_bTwoWayData;

    // HSv4 (legacy handshake) support)
    uint64_t m_ullSndHsLastTime_us;	    //Last SRT handshake request time
    int      m_iSndHsRetryCnt;       //SRT handshake retries left

    bool m_bMessageAPI;
    bool m_bOPT_TsbPd;               // Whether AGENT will do TSBPD Rx (whether peer does, is not agent's problem)
    int m_iOPT_TsbPdDelay;           // Agent's Rx latency
    int m_iOPT_PeerTsbPdDelay;       // Peer's Rx latency for the traffic made by Agent's Tx.
    bool m_bOPT_TLPktDrop;            // Whether Agent WILL DO TLPKTDROP on Rx.
    bool m_bOPT_GroupConnect;
    std::string m_sStreamName;

    int m_iTsbPdDelay_ms;                           // Rx delay to absorb burst in milliseconds
    int m_iPeerTsbPdDelay_ms;                       // Tx delay that the peer uses to absorb burst in milliseconds
    bool m_bTLPktDrop;                           // Enable Too-late Packet Drop
    int64_t m_llInputBW;                         // Input stream rate (bytes/sec)
    int m_iOverheadBW;                           // Percent above input stream rate (applies if m_llMaxBW == 0)
    bool m_bRcvNakReport;                        // Enable Receiver Periodic NAK Reports
private:
    UniquePtr<CCryptoControl> m_pCryptoControl;                            // congestion control SRT class (small data extension)
    CCache<CInfoBlock>* m_pCache;                // network information cache

    // Congestion control
    std::vector<EventSlot> m_Slots[TEV__SIZE];
    Smoother m_Smoother;

    // Attached tool function
    void EmitSignal(ETransmissionEvent tev, EventVariant var);

    // Internal state
    volatile bool m_bListening;                  // If the UDT entit is listening to connection
    volatile bool m_bConnecting;                 // The short phase when connect() is called but not yet completed
    volatile bool m_bConnected;                  // Whether the connection is on or off
    volatile bool m_bClosing;                    // If the UDT entity is closing
    volatile bool m_bShutdown;                   // If the peer side has shutdown the connection
    volatile bool m_bBroken;                     // If the connection has been broken
    volatile bool m_bPeerHealth;                 // If the peer status is normal
    bool m_bOpened;                              // If the UDT entity has been opened
    int m_iBrokenCounter;                        // a counter (number of GC checks) to let the GC tag this socket as disconnected

    int m_iEXPCount;                             // Expiration counter
    int m_iBandwidth;                            // Estimated bandwidth, number of packets per second
    int m_iRTT;                                  // RTT, in microseconds
    int m_iRTTVar;                               // RTT variance
    int m_iDeliveryRate;                         // Packet arrival rate at the receiver side
    int m_iByteDeliveryRate;                     // Byte arrival rate at the receiver side

    uint64_t m_ullLingerExpiration;              // Linger expiration time (for GC to close a socket with data in sending buffer)

    CHandShake m_ConnReq;                        // connection request
    CHandShake m_ConnRes;                        // connection response
    CHandShake::RendezvousState m_RdvState;      // HSv5 rendezvous state
    HandshakeSide m_SrtHsSide;                   // HSv5 rendezvous handshake side resolved from cookie contest (DRAW if not yet resolved)
    int64_t m_llLastReqTime;                     // last time when a connection request is sent

private: // Sending related data
    CSndBuffer* m_pSndBuffer;                    // Sender buffer
    CSndLossList* m_pSndLossList;                // Sender loss list
    CPktTimeWindow<16, 16> m_SndTimeWindow;            // Packet sending time window

    volatile uint64_t m_ullInterval_tk;             // Inter-packet time, in CPU clock cycles
    uint64_t m_ullTimeDiff_tk;                      // aggregate difference in inter-packet time

    volatile int m_iFlowWindowSize;              // Flow control window size
    volatile double m_dCongestionWindow;         // congestion window size

    volatile int32_t m_iSndLastFullAck;          // Last full ACK received
    volatile int32_t m_iSndLastAck;              // Last ACK received
    volatile int32_t m_iSndLastDataAck;          // The real last ACK that updates the sender buffer and loss list
    volatile int32_t m_iSndCurrSeqNo;            // The largest sequence number that has been sent
    //int32_t m_iLastDecSeq;                       // Sequence number sent last decrease occurs (actually part of FileSmoother, formerly CUDTCC)
    int32_t m_iSndLastAck2;                      // Last ACK2 sent back
    uint64_t m_ullSndLastAck2Time;               // The time when last ACK2 was sent back
#ifdef SRT_ENABLE_CBRTIMESTAMP
    uint64_t m_ullSndLastCbrTime_tk;                 // Last timestamp set in a data packet to send (usec)
#endif

    int32_t m_iISN;                              // Initial Sequence Number
    bool m_bPeerTsbPd;                            // Peer accept TimeStamp-Based Rx mode
    bool m_bPeerTLPktDrop;                        // Enable sender late packet dropping
    bool m_bPeerNakReport;                    // Sender's peer (receiver) issues Periodic NAK Reports
    bool m_bPeerRexmitFlag;                   // Receiver supports rexmit flag in payload packets
    int32_t m_iReXmitCount;                      // Re-Transmit Count since last ACK

private: // Receiving related data
    CRcvBuffer* m_pRcvBuffer;               //< Receiver buffer
    CRcvLossList* m_pRcvLossList;           //< Receiver loss list
    std::deque<CRcvFreshLoss> m_FreshLoss;  //< Lost sequence already added to m_pRcvLossList, but not yet sent UMSG_LOSSREPORT for.
    int m_iReorderTolerance;                //< Current value of dynamic reorder tolerance
    int m_iMaxReorderTolerance;             //< Maximum allowed value for dynamic reorder tolerance
    int m_iConsecEarlyDelivery;             //< Increases with every OOO packet that came <TTL-2 time, resets with every increased reorder tolerance
    int m_iConsecOrderedDelivery;           //< Increases with every packet coming in order or retransmitted, resets with every out-of-order packet

    CACKWindow<1024> m_ACKWindow;             //< ACK history window
    CPktTimeWindow<16, 64> m_RcvTimeWindow;   //< Packet arrival time window

    int32_t m_iRcvLastAck;                       //< Last sent ACK
#ifdef ENABLE_LOGGING
    int32_t m_iDebugPrevLastAck;
#endif
    int32_t m_iRcvLastSkipAck;                   // Last dropped sequence ACK
    uint64_t m_ullLastAckTime_tk;                   // Timestamp of last ACK
    int32_t m_iRcvLastAckAck;                    // Last sent ACK that has been acknowledged
    int32_t m_iAckSeqNo;                         // Last ACK sequence number
    int32_t m_iRcvCurrSeqNo;                     // Largest received sequence number

    uint64_t m_ullLastWarningTime;               // Last time that a warning message is sent

    int32_t m_iPeerISN;                          // Initial Sequence Number of the peer side
    uint64_t m_ullRcvPeerStartTime;

    uint32_t m_lSrtVersion;
    uint32_t m_lMinimumPeerSrtVersion;
    uint32_t m_lPeerSrtVersion;

    bool m_bTsbPd;                            // Peer sends TimeStamp-Based Packet Delivery Packets 
    pthread_t m_RcvTsbPdThread;                  // Rcv TsbPD Thread handle
    pthread_cond_t m_RcvTsbPdCond;
    bool m_bTsbPdAckWakeup;                      // Signal TsbPd thread on Ack sent

private: // synchronization: mutexes and conditions
    pthread_mutex_t m_ConnectionLock;            // used to synchronize connection operation

    pthread_cond_t m_SendBlockCond;              // used to block "send" call
    pthread_mutex_t m_SendBlockLock;             // lock associated to m_SendBlockCond

    pthread_mutex_t m_AckLock;                   // used to protected sender's loss list when processing ACK

    pthread_cond_t m_RecvDataCond;               // used to block "recv" when there is no data
    pthread_mutex_t m_RecvDataLock;              // lock associated to m_RecvDataCond

    pthread_mutex_t m_SendLock;                  // used to synchronize "send" call
    pthread_mutex_t m_RecvLock;                  // used to synchronize "recv" call

    pthread_mutex_t m_RcvLossLock;               // Protects the receiver loss list (access: CRcvQueue::worker, CUDT::tsbpd)

    void initSynch();
    void destroySynch();
    void releaseSynch();

private: // Common connection Congestion Control setup
    bool setupCC();
    bool updateCC(ETransmissionEvent, EventVariant arg);
    bool createCrypter(HandshakeSide side, bool bidi);

private: // Generation and processing of packets
    void sendCtrl(UDTMessageType pkttype, void* lparam = NULL, void* rparam = NULL, int size = 0);
    void processCtrl(CPacket& ctrlpkt);
    int packData(ref_t<CPacket> packet, ref_t<uint64_t> ts_tk);
    int processData(CUnit* unit);
    int processConnectRequest(const sockaddr_any& addr, CPacket& packet);
    static void addLossRecord(std::vector<int32_t>& lossrecord, int32_t lo, int32_t hi);
    int32_t bake(const sockaddr_any& addr, int32_t previous_cookie = 0, int correction = 0);

private: // Trace
    uint64_t m_StartTime;                        // timestamp when the UDT entity is started
    int64_t m_llSentTotal;                       // total number of sent data packets, including retransmissions
    int64_t m_llRecvTotal;                       // total number of received packets
    int m_iSndLossTotal;                         // total number of lost packets (sender side)
    int m_iRcvLossTotal;                         // total number of lost packets (receiver side)
    int m_iRetransTotal;                         // total number of retransmitted packets
    int m_iSentACKTotal;                         // total number of sent ACK packets
    int m_iRecvACKTotal;                         // total number of received ACK packets
    int m_iSentNAKTotal;                         // total number of sent NAK packets
    int m_iRecvNAKTotal;                         // total number of received NAK packets
    int m_iSndDropTotal;
    int m_iRcvDropTotal;
    uint64_t m_ullBytesSentTotal;                // total number of bytes sent,  including retransmissions
    uint64_t m_ullBytesRecvTotal;                // total number of received bytes
    uint64_t m_ullRcvBytesLossTotal;             // total number of loss bytes (estimate)
    uint64_t m_ullBytesRetransTotal;             // total number of retransmitted bytes
    uint64_t m_ullSndBytesDropTotal;
    uint64_t m_ullRcvBytesDropTotal;
    int m_iRcvUndecryptTotal;
    uint64_t m_ullRcvBytesUndecryptTotal;
    int64_t m_llSndDurationTotal;		// total real time for sending

    uint64_t m_LastSampleTime;                   // last performance sample time
    int64_t m_llTraceSent;                       // number of packets sent in the last trace interval
    int64_t m_llTraceRecv;                       // number of packets received in the last trace interval
    int m_iTraceSndLoss;                         // number of lost packets in the last trace interval (sender side)
    int m_iTraceRcvLoss;                         // number of lost packets in the last trace interval (receiver side)
    int m_iTraceRetrans;                         // number of retransmitted packets in the last trace interval
    int m_iSentACK;                              // number of ACKs sent in the last trace interval
    int m_iRecvACK;                              // number of ACKs received in the last trace interval
    int m_iSentNAK;                              // number of NAKs sent in the last trace interval
    int m_iRecvNAK;                              // number of NAKs received in the last trace interval
    int m_iTraceSndDrop;
    int m_iTraceRcvDrop;
    int m_iTraceRcvRetrans;
    int m_iTraceReorderDistance;
    double m_fTraceBelatedTime;
    int64_t m_iTraceRcvBelated;
    uint64_t m_ullTraceBytesSent;                // number of bytes sent in the last trace interval
    uint64_t m_ullTraceBytesRecv;                // number of bytes sent in the last trace interval
    uint64_t m_ullTraceRcvBytesLoss;             // number of bytes bytes lost in the last trace interval (estimate)
    uint64_t m_ullTraceBytesRetrans;             // number of bytes retransmitted in the last trace interval
    uint64_t m_ullTraceSndBytesDrop;
    uint64_t m_ullTraceRcvBytesDrop;
    int m_iTraceRcvUndecrypt;
    uint64_t m_ullTraceRcvBytesUndecrypt;
    int64_t m_llSndDuration;			// real time for sending
    int64_t m_llSndDurationCounter;		// timers to record the sending duration

public:

    static const int SELF_CLOCK_INTERVAL = 64;  // ACK interval for self-clocking
    static const int SEND_LITE_ACK = sizeof(int32_t); // special size for ack containing only ack seq
    static const int PACKETPAIR_MASK = 0xF;

    static const size_t MAX_SID_LENGTH = 512;

private: // Timers
    uint64_t m_ullCPUFrequency;               // CPU clock frequency, used for Timer, ticks per microsecond
    uint64_t m_ullNextACKTime_tk;			  // Next ACK time, in CPU clock cycles, same below
    uint64_t m_ullNextNAKTime_tk;			  // Next NAK time

    volatile uint64_t m_ullSYNInt_tk;		  // SYN interval
    volatile uint64_t m_ullACKInt_tk;         // ACK interval
    volatile uint64_t m_ullNAKInt_tk;         // NAK interval
    volatile uint64_t m_ullLastRspTime_tk;    // time stamp of last response from the peer
    volatile uint64_t m_ullLastRspAckTime_tk; // time stamp of last ACK from the peer
    volatile uint64_t m_ullLastSndTime_tk;    // time stamp of last data/ctrl sent (in system ticks)
    uint64_t m_ullMinNakInt_tk;               // NAK timeout lower bound; too small value can cause unnecessary retransmission
    uint64_t m_ullMinExpInt_tk;               // timeout lower bound threshold: too small timeout can cause problem

    int m_iPktCount;				// packet counter for ACK
    int m_iLightACKCount;			// light ACK counter

    uint64_t m_ullTargetTime_tk;			// scheduled time of next packet sending

    void checkTimers();

private: // for UDP multiplexer
    CSndQueue* m_pSndQueue;			// packet sending queue
    CRcvQueue* m_pRcvQueue;			// packet receiving queue
    sockaddr_any m_PeerAddr;        // peer address(es)
    uint32_t m_piSelfIP[4];			// local UDP IP address
    CSNode* m_pSNode;				// node information for UDT list used in snd queue
    CRNode* m_pRNode;               // node information for UDT list used in rcv queue

public: // For smoother
    const CSndQueue* sndQueue() { return m_pSndQueue; }
    const CRcvQueue* rcvQueue() { return m_pRcvQueue; }

private: // for epoll
    std::set<int> m_sPollID;                     // set of epoll ID to trigger
    void addEPoll(const int eid);
    void removeEPoll(const int eid);
};


#endif
