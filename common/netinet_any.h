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
written by
   Haivision Systems Inc.
 *****************************************************************************/

#ifndef INC__NETINET_ANY_H
#define INC__NETINET_ANY_H

#include <cstring>
#include "platform_sys.h"

// This structure should replace every use of sockaddr and its currently
// used specializations, sockaddr_in and sockaddr_in6. This is to simplify
// the use of the original BSD API that relies on type-violating type casts.
// You can use the instances of sockaddr_any in every place where sockaddr is
// required.

struct sockaddr_any
{
    union
    {
        sockaddr_in sin;
        sockaddr_in6 sin6;
        sockaddr sa;
    };
    socklen_t len;

    // Default domain is unspecified, and
    // in this case the size is 0.
    // Note that AF_* (and alias PF_*) types have
    // many various values, of which only
    // AF_INET and AF_INET6 are handled here.
    // Others make the same effect as unspecified.
    explicit sockaddr_any(int domain = AF_UNSPEC)
    {
        // Default domain is "unspecified"
        memset(this, 0, sizeof *this);
        sa.sa_family = domain;
        len = size();
    }

    sockaddr_any(const sockaddr* source, socklen_t namelen)
    {
        memset(this, 0, sizeof *this);
        if (namelen < size(source->sa_family))
            return; // leave this 0-initialized

        switch (source->sa_family)
        {
        case AF_INET:
            sin = *(sockaddr_in*)source;
            break;

        case AF_INET6:
            sin6 = *(sockaddr_in6*)source;
            break;

        default: // do nothing 
            ;
        }
        len = size();
    }

    static socklen_t size(int family)
    {
        switch (family)
        {
        case AF_INET: return socklen_t(sizeof (sockaddr_in));
        case AF_INET6: return socklen_t(sizeof (sockaddr_in6));

        default: return 0; // fallback
        }
    }

    bool empty() const
    {
        switch (sa.sa_family)
        {
        case AF_INET:
            return sin.sin_port == 0 && sin.sin_addr.s_addr == 0;

        case AF_INET6:
            if (sin6.sin6_port != 0)
                return false;

            // This length expression should result in 4, as
            // the size of sin6_addr is 16.
            for (size_t i = 0; i < (sizeof sin6.sin6_addr)/sizeof(int32_t); ++i)
                if (((int32_t*)&sin6.sin6_addr)[i] != 0)
                    return false;
            return true;
        }

        return true; // unspec-family address is always empty
    }

    socklen_t size() const
    {
        return size(sa.sa_family);
    }

    int family() const { return sa.sa_family; }
    void family(int val)
    {
        sa.sa_family = val;
        len = size();
    }

    // port is in exactly the same location in both sin and sin6
    // and has the same size. This is actually yet another common
    // field, just not mentioned in the sockaddr structure.
    uint16_t& r_port() { return sin.sin_port; }
    uint16_t r_port() const { return sin.sin_port; }
    int hport() const { return ntohs(sin.sin_port); }

    void hport(int value)
    {
        // Port is fortunately located at the same position
        // in both sockaddr_in and sockaddr_in6 and has the
        // same size.
        sin.sin_port = htons(value);
    }

    sockaddr* get() { return &sa; }
    const sockaddr* get() const { return &sa; }
    sockaddr* operator&() { return &sa; }
    const sockaddr* operator&() const { return &sa; }

    operator sockaddr&() { return sa; }
    operator const sockaddr&() const { return sa; }

    template <int> struct TypeMap;

    template <int af_domain>
    typename TypeMap<af_domain>::type& get();

    struct Equal
    {
        bool operator()(const sockaddr_any& c1, const sockaddr_any& c2)
        {
            return memcmp(&c1, &c2, sizeof(c1)) == 0;
        }
    };

    bool operator==(const sockaddr_any& c2) const
    {
        return Equal()(*this, c2);
    }

    bool operator!=(const sockaddr_any& c2) const { return !(*this == c2); }

    struct EqualAddress
    {
        bool operator()(const sockaddr_any& c1, const sockaddr_any& c2)
        {
            if ( c1.sa.sa_family == AF_INET )
            {
                return c1.sin.sin_addr.s_addr == c2.sin.sin_addr.s_addr;
            }

            if ( c1.sa.sa_family == AF_INET6 )
            {
                return memcmp(&c1.sin6.sin6_addr, &c2.sin6.sin6_addr, sizeof (in6_addr)) == 0;
            }

            return false;
        }

    };

    bool equal_address(const sockaddr_any& rhs) const
    {
        return EqualAddress()(*this, rhs);
    }

    struct Less
    {
        bool operator()(const sockaddr_any& c1, const sockaddr_any& c2)
        {
            return memcmp(&c1, &c2, sizeof(c1)) < 0;
        }
    };
};

template<> struct sockaddr_any::TypeMap<AF_INET> { typedef sockaddr_in type; };
template<> struct sockaddr_any::TypeMap<AF_INET6> { typedef sockaddr_in6 type; };

template <>
inline sockaddr_any::TypeMap<AF_INET>::type& sockaddr_any::get<AF_INET>() { return sin; }
template <>
inline sockaddr_any::TypeMap<AF_INET6>::type& sockaddr_any::get<AF_INET6>() { return sin6; }

#endif
