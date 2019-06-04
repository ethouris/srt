/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

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

#ifndef INC__HANDSHAKE_H
#define INC__HANDSHAKE_H

#include "crypto.h"
#include "utilities.h"

typedef Bits<31, 16> HS_CMDSPEC_CMD;
typedef Bits<15, 0> HS_CMDSPEC_SIZE;

enum SrtOptions
{
    SRT_OPT_TSBPDSND  = BIT(0), /* Timestamp-based Packet delivery real-time data sender */
    SRT_OPT_TSBPDRCV  = BIT(1), /* Timestamp-based Packet delivery real-time data receiver */
    SRT_OPT_HAICRYPT  = BIT(2), /* HaiCrypt AES-128/192/256-CTR */
    SRT_OPT_TLPKTDROP = BIT(3), /* Drop real-time data packets too late to be processed in time */
    SRT_OPT_NAKREPORT = BIT(4), /* Periodic NAK report */
    SRT_OPT_REXMITFLG = BIT(5), // One bit in payload packet msgno is "retransmitted" flag
                                // (this flag can be reused for something else, when pre-1.2.0 versions are all abandoned)
    SRT_OPT_STREAM    = BIT(6)
};


std::string SrtFlagString(int32_t flags);

const int SRT_CMD_REJECT = 0, // REJECT is only a symbol for return type
      SRT_CMD_HSREQ = 1,
      SRT_CMD_HSRSP = 2,
      SRT_CMD_KMREQ = 3,
      SRT_CMD_KMRSP = 4,
      SRT_CMD_SID = 5,
      SRT_CMD_CONGESTION = 6,
      SRT_CMD_NONE = -1; // for cases when {no pong for ping is required} | {no extension block found}

enum SrtDataStruct
{
    SRT_HS_VERSION = 0,
    SRT_HS_FLAGS,
    SRT_HS_LATENCY,

    // Keep it always last
    SRT_HS__SIZE
};

// For HSv5 the lo and hi part is used for particular side's latency
typedef Bits<31, 16> SRT_HS_LATENCY_RCV;
typedef Bits<15, 0> SRT_HS_LATENCY_SND;
// For HSv4 only the lower part is used.
typedef Bits<15, 0> SRT_HS_LATENCY_LEG;


// XXX These structures are currently unused. The code can be changed
// so that these are used instead of manual tailoring of the messages.
struct SrtHandshakeExtension
{
protected:

   uint32_t m_SrtCommand; // Used only in extension

public:
   SrtHandshakeExtension(int cmd)
   {
       m_SrtCommand = cmd;
   }

   void setCommand(int cmd)
   {
       m_SrtCommand = cmd;
   }

};

struct SrtHSRequest: public SrtHandshakeExtension
{

    typedef Bits<31, 16> SRT_HSTYPE_ENCFLAGS;
    typedef Bits<15, 0> SRT_HSTYPE_HSFLAGS;

    // For translating PBKEYLEN into crypto flags
    // This value is 16, 24, 32; after cutting off
    // the leftmost 3 bits, it is 2, 3, 4.
    typedef Bits<5, 3> SRT_PBKEYLEN_BITS;

    // This value fits ins SRT_HSTYPE_HSFLAGS.
    //  ....                                HAIVISIOn
    static const int32_t SRT_MAGIC_CODE = 0x4A17;

    static int32_t wrapFlags(bool withmagic, int crypto_keylen)
    {
        int32_t base = withmagic ? SRT_MAGIC_CODE : 0;
        return base | SRT_HSTYPE_ENCFLAGS::wrap( SRT_PBKEYLEN_BITS::unwrap(crypto_keylen) );
    }

private:
    friend class CHandShake;

    static const size_t SRT_HS_SIZE = 4*sizeof(uint32_t); // 4 existing fields
    static const size_t SRT_EXT_HS_SIZE = 2*sizeof(uint32_t) + SRT_HS_SIZE; // SRT magic and SRT HS type, used only in UDT HS ext

    typedef Bits<15, 0> SRT_TSBPD_DELAY;

    uint32_t m_iSrtVersion;
    uint32_t m_iSrtFlags;
    uint32_t m_iSrtTsbpd;
    uint32_t m_iSrtReserved;

public:

    SrtHSRequest(): SrtHandshakeExtension(SRT_CMD_HSREQ), m_iSrtVersion(), m_iSrtFlags(), m_iSrtTsbpd(), m_iSrtReserved() {}

    void setVersion(uint32_t v) { m_iSrtVersion = v; }
    uint32_t version() const { return m_iSrtVersion; }

    void setFlag(SrtOptions opt) { m_iSrtFlags |= uint32_t(opt); }
    void clearFlag(SrtOptions opt) { m_iSrtFlags &= ~opt; }
    uint32_t flags() const { return m_iSrtFlags; }

    void setTsbPdDelay(uint16_t delay) { m_iSrtTsbpd |= SRT_TSBPD_DELAY::wrap(delay); }
    // Unknown what the 1-16 bits have to be used for.
    uint16_t tsbPdDelay() const
    {
        return SRT_TSBPD_DELAY::unwrap(m_iSrtTsbpd);
    }

    size_t size() const { return SRT_EXT_HS_SIZE; }

    bool serialize(char* p, size_t size) const;
    bool deserialize(const char* mem, size_t size);
};

struct SrtKMRequest: public SrtHandshakeExtension
{
    uint32_t m_iKmState;
    char m_aKey[1]; // dynamic size
};


////////////////////////////////////////////////////////////////////////////////

enum UDTRequestType
{
    URQ_INDUCTION_TYPES = 0, // XXX used to check in one place. Consdr rm.

    URQ_INDUCTION = 1, // First part for client-server connection
    URQ_WAVEAHAND = 0, // First part for rendezvous connection

    URQ_CONCLUSION = -1, // Second part of handshake negotiation
    URQ_AGREEMENT = -2, // Extra (last) step for rendezvous only
    URQ_DONE = -3,      // Special value used only in state-switching, to state that nothing should be sent in response

    // Note: the client-server connection uses:
    // --> INDUCTION (empty)
    // <-- INDUCTION (cookie)
    // --> CONCLUSION (cookie)
    // <-- CONCLUSION (ok)

    // The rendezvous HSv4 (legacy):
    // --> WAVEAHAND (effective only if peer is also connecting)
    // <-- CONCLUSION (empty) (consider yourself connected upon reception)
    // --> AGREEMENT (sent as a response for conclusion, requires no response)

    // The rendezvous HSv5 (using SRT extensions):
    // --> WAVEAHAND (with cookie)
    // --- (selecting INITIATOR/RESPONDER by cookie contest - comparing one another's cookie)
    // <-- CONCLUSION (without extensions, if RESPONDER, with extensions, if INITIATOR)
    // --> CONCLUSION (with response extensions, if RESPONDER)
    // <-- AGREEMENT (sent exclusively by INITIATOR upon reception of CONCLUSIOn with response extensions)

    // Errors reported by the peer, also used as useless error codes
    // in handshake processing functions.
    URQ_FAILURE_TYPES = 1000,

    // Repeated codes from SRT_REJ_* here for convenience and
    // compiler warning prevention, but they should not be used directly.
    URQ_REJ_SYSTEM,      // broken due to system function error
    URQ_REJ_PEER,        // connection was rejected by peer
    URQ_REJ_RESOURCE,    // internal problem with resource allocation
    URQ_REJ_ROGUE,       // incorrect data in handshake messages
    URQ_REJ_BACKLOG,     // backlog exceeded
    URQ_REJ_IPE,         // internal program error
    URQ_REJ_CLOSE,       // socket is closing
    URQ_REJ_VERSION,     // peer is older version than agent's minimum set
    URQ_REJ_RDVCOOKIE,   // rendezvous cookie collision
    URQ_REJ_BADSECRET,   // wrong password
    URQ_REJ_STRICTENC,   // illegal setup for strictly-encrypted
    URQ_REJ_MESSAGEAPI,  // streamapi/messageapi collision
    URQ_REJ_CONGESTION,  // incompatible congestion-controller type
    URQ_REJ_FILTER       // incompatible packet filter
};

inline UDTRequestType URQFailure(SRT_REJECT_REASON reason)
{
    return UDTRequestType(URQ_FAILURE_TYPES + int(reason));
}

inline SRT_REJECT_REASON RejectReasonForURQ(UDTRequestType req)
{
    if (req < URQ_FAILURE_TYPES || req - URQ_FAILURE_TYPES >= SRT_REJ__SIZE)
        return SRT_REJ_UNKNOWN;
    return SRT_REJECT_REASON( (req - URQ_FAILURE_TYPES) | SRT_REJ_PEERREP);
}

// DEPRECATED values. Use URQFailure(SRT_REJECT_REASON).
const UDTRequestType URQ_ERROR_REJECT SRT_ATR_DEPRECATED = (UDTRequestType)1002; // == 1000 + SRT_REJ_PEER
const UDTRequestType URQ_ERROR_INVALID SRT_ATR_DEPRECATED = (UDTRequestType)1004; // == 1000 + SRT_REJ_ROGUE

// XXX Change all uses of that field to UDTRequestType when possible
#if ENABLE_LOGGING
std::string RequestTypeStr(UDTRequestType);
#else
inline std::string RequestTypeStr(UDTRequestType) { return ""; }
#endif


class CHandShake
{
public:
   CHandShake();

   int store_to(char* buf, ref_t<size_t> size);
   int load_from(const char* buf, size_t size);

public:
   // This is the size of SERIALIZED handshake.
   // Might be defined as simply sizeof(CHandShake), but the
   // enum values would have to be forced as int32_t, which is only
   // available in C++11. Theoretically they are all 32-bit, but
   // such a statement is not reliable and not portable.
   static const size_t m_iContentSize = 48;	// Size of hand shake data

   // Extension flags

    static const int32_t HS_EXT_HSREQ = BIT(0);
    static const int32_t HS_EXT_KMREQ = BIT(1);
    static const int32_t HS_EXT_CONFIG  = BIT(2);

    static std::string ExtensionFlagStr(int32_t fl);

    // Applicable only when m_iVersion == HS_VERSION_SRT1
    int32_t flags() { return m_iType; }

public:
   int32_t m_iVersion;          // UDT version (HS_VERSION_* symbols)
   int32_t m_iType;             // UDT4: socket type (only UDT_DGRAM is valid); SRT1: extension flags
   int32_t m_iISN;              // random initial sequence number
   int32_t m_iMSS;              // maximum segment size
   int32_t m_iFlightFlagSize;   // flow control window size
   UDTRequestType m_iReqType;   // handshake stage
   int32_t m_iID;		// socket ID
   int32_t m_iCookie;		// cookie
   uint32_t m_piPeerIP[4];	// The IP address that the peer's UDP port is bound to

   bool m_extension;

   std::string show();

// The rendezvous state machine used in HSv5 only (in HSv4 everything is happening the old way).
//
// The WAVING state is the very initial state of the rendezvous connection and restored after the
// connection is closed.
// The ATTENTION and FINE are two alternative states that are transited to from WAVING. The possible
// situations are:
// - "serial arrangement": one party transits to ATTENTION and the other party transits to FINE
// - "parallel arrangement" both parties transit to ATTENTION
//
// Parallel arrangement is a "virtually impossible" case, in which both parties must send the first
// URQ_WAVEAHAND message in a perfect time synchronization, when they are started at exactly the same
// time, on machines with exactly the same performance and all things preceding the message sending
// have taken perfectly identical amount of time. This isn't anyhow possible otherwise because if
// the clients have started at different times, the one who started first sends a message and the
// system of the receiver buffers this message even before the client binds the port for enough long
// time so that it outlasts also the possible second, repeated waveahand.
enum RendezvousState
{
    RDV_INVALID,    //< This socket wasn't prepared for rendezvous process. Reject any events.
    RDV_WAVING,     //< Initial state for rendezvous. No contact seen from the peer.
    RDV_ATTENTION,  //< When received URQ_WAVEAHAND. [WAVING]:URQ_WAVEAHAND  --> [ATTENTION].
    RDV_FINE,       //< When received URQ_CONCLUSION. [WAVING]:URQ_CONCLUSION --> [FINE].
    RDV_INITIATED,  //< When received URQ_CONCLUSION+HSREQ extension in ATTENTION state. 
    RDV_CONNECTED   //< Final connected state. [ATTENTION]:URQ_CONCLUSION --> [CONNECTED] <-- [FINE]:URQ_AGREEMENT.
};

#if ENABLE_LOGGING
static std::string RdvStateStr(RendezvousState s);
#else
static std::string RdvStateStr(RendezvousState) { return ""; }
#endif

};


#endif
