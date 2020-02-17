/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2019 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */
#pragma once
#ifndef __SRT_SYNC_H__
#define __SRT_SYNC_H__

//#define USE_STL_CHRONO
//#define ENABLE_CXX17

#include <cstdlib>
#include <pthread.h>
#include "utilities.h"

namespace srt
{
namespace sync
{
using namespace std;

template <class _Clock>
class Duration
{
public:
    Duration()
        : m_duration(0)
    {
    }

    explicit Duration(int64_t d)
        : m_duration(d)
    {
    }

public:
    inline int64_t count() const { return m_duration; }

    static Duration zero() { return Duration(); }

public: // Relational operators
    inline bool operator>=(const Duration& rhs) const { return m_duration >= rhs.m_duration; }
    inline bool operator>(const Duration& rhs) const { return m_duration > rhs.m_duration; }
    inline bool operator==(const Duration& rhs) const { return m_duration == rhs.m_duration; }
    inline bool operator!=(const Duration& rhs) const { return m_duration != rhs.m_duration; }
    inline bool operator<=(const Duration& rhs) const { return m_duration <= rhs.m_duration; }
    inline bool operator<(const Duration& rhs) const { return m_duration < rhs.m_duration; }

public: // Assignment operators
    inline void operator*=(const double mult) { m_duration = static_cast<int64_t>(m_duration * mult); }
    inline void operator+=(const Duration& rhs) { m_duration += rhs.m_duration; }
    inline void operator-=(const Duration& rhs) { m_duration -= rhs.m_duration; }

    inline Duration operator+(const Duration& rhs) const { return Duration(m_duration + rhs.m_duration); }
    inline Duration operator-(const Duration& rhs) const { return Duration(m_duration - rhs.m_duration); }
    inline Duration operator*(const int& rhs) const { return Duration(m_duration * rhs); }

private:
    // int64_t range is from -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807
    int64_t m_duration;
};

template <class _Clock>
class TimePoint;

class steady_clock
{
public:
    typedef Duration<steady_clock>  duration;
    typedef TimePoint<steady_clock> time_point;

public:
    static time_point now();
    static time_point zero();
};

template <class _Clock>
class TimePoint
{ // represents a point in time
public:
    TimePoint()
        : m_timestamp(0)
    {
    }

    explicit TimePoint(uint64_t tp)
        : m_timestamp(tp)
    {
    }

    TimePoint(const TimePoint<_Clock>& other)
        : m_timestamp(other.m_timestamp)
    {
    }

    ~TimePoint() {}

public: // Relational operators
    inline bool operator<(const TimePoint<_Clock>& rhs) const { return m_timestamp < rhs.m_timestamp; }
    inline bool operator<=(const TimePoint<_Clock>& rhs) const { return m_timestamp <= rhs.m_timestamp; }
    inline bool operator==(const TimePoint<_Clock>& rhs) const { return m_timestamp == rhs.m_timestamp; }
    inline bool operator!=(const TimePoint<_Clock>& rhs) const { return m_timestamp != rhs.m_timestamp; }
    inline bool operator>=(const TimePoint<_Clock>& rhs) const { return m_timestamp >= rhs.m_timestamp; }
    inline bool operator>(const TimePoint<_Clock>& rhs) const { return m_timestamp > rhs.m_timestamp; }

public: // Arithmetic operators
    inline Duration<_Clock> operator-(const TimePoint<_Clock>& rhs) const
    {
        return Duration<_Clock>(m_timestamp - rhs.m_timestamp);
    }
    inline TimePoint operator+(const Duration<_Clock>& rhs) const { return TimePoint(m_timestamp + rhs.count()); }
    inline TimePoint operator-(const Duration<_Clock>& rhs) const { return TimePoint(m_timestamp - rhs.count()); }

public: // Assignment operators
    inline void operator=(const TimePoint<_Clock>& rhs) { m_timestamp = rhs.m_timestamp; }
    inline void operator+=(const Duration<_Clock>& rhs) { m_timestamp += rhs.count(); }
    inline void operator-=(const Duration<_Clock>& rhs) { m_timestamp -= rhs.count(); }

public: //
#if HAVE_FULL_CXX11
    static inline ATR_CONSTEXPR TimePoint min() { return TimePoint(numeric_limits<uint64_t>::min()); }
    static inline ATR_CONSTEXPR TimePoint max() { return TimePoint(numeric_limits<uint64_t>::max()); }
#else
#ifndef UINT64_MAX
#define UNDEF_UINT64_MAX
#define UINT64_MAX 0xffffffffffffffffULL
#endif
    static inline TimePoint min() { return TimePoint(0); }
    static inline TimePoint max() { return TimePoint(UINT64_MAX); }

#ifdef UNDEF_UINT64_MAX
#undef UINT64_MAX
#endif
#endif

public:
    uint64_t         us_since_epoch() const;
    Duration<_Clock> time_since_epoch() const;

public:
    bool is_zero() const { return m_timestamp == 0; }

private:
    uint64_t m_timestamp;
};

inline TimePoint<srt::sync::steady_clock> steady_clock::zero()
{
    return TimePoint<steady_clock>(0);
}


template <>
uint64_t srt::sync::TimePoint<srt::sync::steady_clock>::us_since_epoch() const;

template <>
srt::sync::Duration<srt::sync::steady_clock> srt::sync::TimePoint<srt::sync::steady_clock>::time_since_epoch() const;

inline Duration<steady_clock> operator*(const int& lhs, const Duration<steady_clock>& rhs)
{
    return rhs * lhs;
}

inline int64_t count_microseconds(const TimePoint<steady_clock> tp)
{
    return static_cast<int64_t>(tp.us_since_epoch());
}

int64_t count_microseconds(const steady_clock::duration& t);
int64_t count_milliseconds(const steady_clock::duration& t);
int64_t count_seconds(const steady_clock::duration& t);

Duration<steady_clock> microseconds_from(int64_t t_us);
Duration<steady_clock> milliseconds_from(int64_t t_ms);
Duration<steady_clock> seconds_from(int64_t t_s);

inline bool is_zero(const TimePoint<steady_clock>& t) { return t.is_zero(); }


///////////////////////////////////////////////////////////////////////////////
//
// Mutex section
//
///////////////////////////////////////////////////////////////////////////////

/// Mutex is a class wrapper, that should mimic the std::chrono::mutex class.
/// At the moment the extra function ref() is temporally added to allow calls
/// to pthread_cond_timedwait(). Will be removed by introducing CEvent.
class MutexImp
{
    friend class SyncEvent;

public:
    MutexImp();
    ~MutexImp();

public:
    int lock();
    int unlock();

    /// @return     true if the lock was acquired successfully, otherwise false
    bool try_lock();

    // TODO: To be removed with introduction of the CEvent.
    pthread_mutex_t& ref() { return m_mutex; }

private:
    pthread_mutex_t m_mutex;
};

/// A pthread version of std::chrono::scoped_lock<mutex> (or lock_guard for C++11)
class ScopedLock
{
public:
    ScopedLock(MutexImp& m);
    ~ScopedLock();

private:
    MutexImp& m_mutex;
};

/// A pthread version of std::chrono::unique_lock<mutex>
class UniqueLock
{
    friend class SyncEvent;

public:
    UniqueLock(MutexImp &m);
    ~UniqueLock();

public:
    void unlock();
    MutexImp* mutex(); // reflects C++11 unique_lock::mutex()

private:
    int m_iLocked;
    MutexImp& m_Mutex;
};



#if ENABLE_THREAD_LOGGING
/// The purpose of this typedef is to reduce the number of changes in the code (renamings)
/// and produce less merge conflicts with some other parallel work done.
/// TODO: Replace CGuard with ScopedLock. Use UniqueLock only when required.
typedef UniqueLock CGuardImp;

struct CMutexWrapper
{
    typedef MutexImp sysobj_t;
    MutexImp in_sysobj;
    std::string lockname;

    int lock() { return in_sysobj.lock(); }
    int unlock() { return in_sysobj.unlock(); }
    int try_lock() { return in_sysobj.try_lock(); }

    // TODO: To be removed with introduction of the CEvent.
    pthread_mutex_t& ref() { return in_sysobj.ref(); }

    //MutexImp* operator& () { return &in_sysobj; }

   // Turned explicitly to string because this is exposed only for logging purposes.
   std::string show()
   {
       std::ostringstream os;
       os << (&in_sysobj);
       return os.str();
   }

};

typedef CMutexWrapper Mutex;

struct CGuardLog
{
    CGuardLog(Mutex& lock);
};

struct CGuard: CGuardLog, CGuardImp
{
    CGuard(Mutex& lock);
    ~CGuard();
};


struct CConditionWrapper
{
    typedef pthread_cond_t sysobj_t;
    pthread_cond_t in_sysobj;
    std::string cvname;
};

typedef CConditionWrapper CCondition;

template<class SysObj>
inline typename SysObj::sysobj_t* RawAddr(SysObj& obj)
{
    return &obj.in_sysobj;
}

#else
typedef MutexImp Mutex;
typedef ::pthread_cond_t CCondition;
typedef UniqueLock CGuard;

// Note: This cannot be defined as overloaded for
// two different types because on some platforms
// the pthread_cond_t and pthread_mutex_t are distinct
// types, while on others they resolve to the same type.
template <class SysObj>
inline SysObj* RawAddr(SysObj& m) { return &m; }
#endif

bool isthread(const pthread_t& thrval);

bool jointhread(pthread_t& thr, void*& result);
bool jointhread(pthread_t& thr);

#if ENABLE_THREAD_LOGGING
void createMutex(Mutex& lock, const char* name);
#else
// For non-thread-logging cases this function is only a stub.
inline void createMutex(Mutex& , const char* ) {}
#endif
void createCond(CCondition& cond, const char* name);
void createCond_monotonic(CCondition& cond, const char* name);
void releaseCond(CCondition& cond);

#if ENABLE_THREAD_LOGGING
// Will do extra logging things
bool enterCS(Mutex &m, explicit_t<bool> block = true);
void leaveCS(Mutex &m);
#else
inline bool enterCS(Mutex &m, bool dolock = true) { if (!dolock) { return m.try_lock(); } else { m.lock(); return true; } }
inline void leaveCS(Mutex &m) { m.unlock(); }
#endif

class InvertedLock
{
    Mutex *m_pMutex;

  public:
    InvertedLock(Mutex *m)
        : m_pMutex(m)
    {
        if (!m_pMutex)
            return;

        leaveCS(*m_pMutex);
    }

    InvertedLock(Mutex& m)
        : m_pMutex(&m)
    {
        leaveCS(*m_pMutex);
    }

    ~InvertedLock()
    {
        if (!m_pMutex)
            return;
        enterCS(*m_pMutex);
    }
};

///////////////////////////////////////////////////////////////////////////////
//
// Event (CV) section
//
///////////////////////////////////////////////////////////////////////////////

inline void SleepFor(const steady_clock::duration& t)
{
#ifndef _WIN32
    usleep(count_microseconds(t)); // microseconds
#else
    Sleep(count_milliseconds(t));
#endif
}

// This class is used for condition variable combined with mutex by different ways.
// This should provide a cleaner API around locking with debug-logging inside.
class CSync
{
    CCondition* m_cond;
    Mutex* m_mutex;

public:
    enum Nolock { NOLOCK };

    // Locked version: must be declared only after the declaration of CGuard,
    // which has locked the mutex. On this delegate you should call only
    // signal_locked() and pass the CGuard variable that should remain locked.
    // Also wait() and wait_for() can be used only with this socket.
    CSync(CCondition& cond, CGuard& g);

    // This is only for one-shot signaling. This doesn't need a CGuard
    // variable, only the mutex itself. Only lock_signal() can be used.
    CSync(CCondition& cond, Mutex& mutex, Nolock);

    // An alternative method
    static CSync nolock(CCondition& cond, Mutex& m)
    {
        return CSync(cond, m, NOLOCK);
    }

    // COPY CONSTRUCTOR: DEFAULT!

    // Wait indefinitely, until getting a signal on CV.
    void wait();

    // Wait only for a given time delay (in microseconds). This function
    // extracts first current time using steady_clock::now().
    bool wait_for(const steady_clock::duration& delay);
    bool wait_for_monotonic(const steady_clock::duration& delay);

    // Wait until the given time is achieved. This actually
    // refers to wait_for for the time remaining to achieve
    // given time.
    bool wait_until(const steady_clock::time_point& exptime);

    // You can signal using two methods:
    // - lock_signal: expect the mutex NOT locked, lock it, signal, then unlock.
    // - signal: expect the mutex locked, so only issue a signal, but you must pass the CGuard that keeps the lock.
    void lock_signal();

    // Static ad-hoc version
    static void lock_signal(CCondition& cond, Mutex& m);
    static void lock_broadcast(CCondition& cond, Mutex& m);

    void signal_locked(CGuard& lk);
    void signal_relaxed();
    static void signal_relaxed(CCondition& cond);
    static void broadcast_relaxed(CCondition& cond);
};

class SyncEvent
{
public:
    /// Atomically releases lock, blocks the current executing thread,
    /// and adds it to the list of threads waiting on* this.
    /// The thread will be unblocked when notify_all() or notify_one() is executed,
    /// or when the relative timeout rel_time expires.
    /// It may also be unblocked spuriously.
    /// When unblocked, regardless of the reason, lock is reacquiredand wait_for() exits.
    ///
    /// @return result of pthread_cond_wait(...) function call
    ///
    static int wait_for(pthread_cond_t* cond, pthread_mutex_t* mutex, const steady_clock::duration& rel_time);
    static int wait_for_monotonic(pthread_cond_t* cond, pthread_mutex_t* mutex, const steady_clock::duration& rel_time);
    
#if ENABLE_THREAD_LOGGING
    int wait_for(CConditionWrapper* cond, CMutexWrapper* mutex, const steady_clock::duration& rel_time)
    {
        return wait_for(&cond->in_sysobj, &mutex->in_sysobj.ref(), rel_time);
    }
    int wait_for_monotonic(CConditionWrapper* cond, CMutexWrapper* mutex, const steady_clock::duration& rel_time)
    {
        return wait_for_monotonic(&cond->in_sysobj, &mutex->in_sysobj.ref(), rel_time);
    }
#endif

};

/// Print steady clock timepoint in a human readable way.
/// days HH:MM::SS.us [STD]
/// Example: 1D 02:12:56.123456
///
/// @param [in] steady clock timepoint
/// @returns a string with a formatted time representation
std::string FormatTime(const steady_clock::time_point& time);

/// Print steady clock timepoint relative to the current system time
/// Date HH:MM::SS.us [SYS]
/// @param [in] steady clock timepoint
/// @returns a string with a formatted time representation
std::string FormatTimeSys(const steady_clock::time_point& time);

// Debug purposes
#if ENABLE_THREAD_LOGGING
void ThreadCheckAffinity(const char* function, pthread_t thr);
#define THREAD_CHECK_AFFINITY(thr) srt::sync::ThreadCheckAffinity(__FUNCTION__, thr)
#else
#define THREAD_CHECK_AFFINITY(thr)
#endif

enum eDurationUnit {DUNIT_S, DUNIT_MS, DUNIT_US};

template <eDurationUnit u>
struct DurationUnitName;

template<>
struct DurationUnitName<DUNIT_US>
{
    static const char* name() { return "us"; }
    static double count(const steady_clock::duration& dur) { return count_microseconds(dur); }
};

template<>
struct DurationUnitName<DUNIT_MS>
{
    static const char* name() { return "ms"; }
    static double count(const steady_clock::duration& dur) { return count_microseconds(dur)/1000.0; }
};

template<>
struct DurationUnitName<DUNIT_S>
{
    static const char* name() { return "s"; }
    static double count(const steady_clock::duration& dur) { return count_microseconds(dur)/1000000.0; }
};

template<eDurationUnit UNIT>
inline std::string FormatDuration(const steady_clock::duration& dur)
{
    return Sprint(DurationUnitName<UNIT>::count(dur)) + DurationUnitName<UNIT>::name();
}

inline std::string FormatDuration(const steady_clock::duration& dur)
{
    return FormatDuration<DUNIT_US>(dur);
}

}; // namespace sync
}; // namespace srt

#endif // __SRT_SYNC_H__
