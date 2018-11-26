/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 * Written by:
 *             Haivision Systems Inc.
 */

#include <gtest/gtest.h>

#include "srt.h"


/*
 * TESTING SCENARIO
 * Both peers exchange HandShake v5.
 * Listener is sender   in a non-blocking mode
 * Caller   is receiver in a     blocking mode
 * 
 *     Caller               | Listener             | Passwords | Connection
 *     STRICTENC | Password | STRICTENC | Password |           |     result
 * ------------------------------------------------------------------------
 *  1.       yes        set         yes        set       match       accept
 *  2.       yes        set         yes        set    mismatch       reject
 *  3.         X    not set         yes        set           X       reject
 *  4.       yes        set           X    not set           X       reject
 *  5.         X    not set           X    not set           X       accept
 *  6.       yes        set          no        set       match       accept
 *  7.       yes        set          no        set    mismatch       reject
 *  8.         X    not set          no        set           X       accept
 *  9.        no        set         yes        set       match       accept
 * 10.        no        set         yes        set    mismatch       reject
 * 11.        no        set           X    not set           X       accept
 * 12.        no        set          no        set       match       accept
 * 13.        no        set          no        set    mismatch       reject
 * 
*/


class TestStrictEncryption
    : public ::testing::Test
{
protected:
    TestStrictEncryption()
    {
        // initialization code here
    }

    ~TestStrictEncryption()
    {
        // cleanup any pending stuff, but no exceptions allowed
    }
    
protected:
    
    // SetUp() is run immediately before a test starts.
    void SetUp()
    {
        ASSERT_EQ(srt_startup(), 0);
        
        m_pollid = srt_epoll_create();
        ASSERT_GE(m_pollid, 0);
        
        m_caller_socket = srt_create_socket();
        ASSERT_NE(m_caller_socket, SRT_INVALID_SOCK);

        ASSERT_NE(srt_setsockflag(m_caller_socket, SRTO_SENDER, &s_yes, sizeof s_yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_RCVSYN,    &s_yes,  sizeof s_yes),  SRT_ERROR); // blocking mode
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_SNDSYN,    &s_yes,  sizeof s_yes),  SRT_ERROR); // blocking mode
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_TSBPDMODE, &s_yes, sizeof s_yes),   SRT_ERROR);

        m_listener_socket = srt_create_socket();
        ASSERT_NE(m_listener_socket, SRT_INVALID_SOCK);

        ASSERT_NE(srt_setsockflag(m_listener_socket, SRTO_SENDER, &s_no, sizeof s_no), SRT_ERROR);
        ASSERT_NE(srt_setsockopt (m_listener_socket, 0, SRTO_RCVSYN,    &s_no,   sizeof s_no),  SRT_ERROR); // for async accept
        ASSERT_NE(srt_setsockopt (m_listener_socket, 0, SRTO_SNDSYN,    &s_no,   sizeof s_no),  SRT_ERROR); // for async accept
        ASSERT_NE(srt_setsockopt (m_listener_socket, 0, SRTO_TSBPDMODE, &s_yes,  sizeof s_yes), SRT_ERROR);
        
        // Will use this epoll to wait for srt_accept(...)
        const int epoll_out = SRT_EPOLL_OUT | SRT_EPOLL_ERR;
        ASSERT_NE(srt_epoll_add_usock(m_pollid, m_listener_socket, &epoll_out), SRT_ERROR);
    }

    void TearDown()
    {
        // code here will be called just after the test completes
        // ok to through exceptions from here if needed
        ASSERT_NE(srt_close(m_caller_socket),   SRT_ERROR);
        ASSERT_NE(srt_close(m_listener_socket), SRT_ERROR);
        srt_cleanup();
    }
    
    
public:
    
    
    void SetStrictEncryption(bool strict_caller, bool strict_listener)
    {
        static_assert(sizeof s_yes == sizeof s_no, "Type sizes mismatch!");
        
        ASSERT_NE(srt_setsockopt(m_caller_socket,   0, SRTO_STRICTENC, strict_caller   ? &s_yes : &s_no, sizeof s_yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt(m_listener_socket, 0, SRTO_STRICTENC, strict_listener ? &s_yes : &s_no, sizeof s_yes), SRT_ERROR);
    }
    
    
    int SetPassword(const std::basic_string<char> &pwd, const bool is_caller)
    {
        const SRTSOCKET socket = is_caller ? m_caller_socket : m_listener_socket;
        return srt_setsockopt(socket, 0, SRTO_PASSPHRASE, pwd.c_str(), pwd.size());
    }
    
    
    void SetPasswords(const std::basic_string<char> &caller_pwd, const std::basic_string<char> &listener_pwd)
    {
        ASSERT_NE(srt_setsockopt(m_caller_socket,   0, SRTO_PASSPHRASE, caller_pwd.c_str(),   caller_pwd.size()),   SRT_ERROR);
        ASSERT_NE(srt_setsockopt(m_listener_socket, 0, SRTO_PASSPHRASE, listener_pwd.c_str(), listener_pwd.size()), SRT_ERROR);
    }
    
    
    int GetKMState(bool is_caller)
    {
        const SRTSOCKET socket = is_caller ? m_caller_socket : m_listener_socket;
        int km_state = 0;
        int opt_size = sizeof km_state;
        srt_getsockopt(socket, 0, SRTO_KMSTATE, reinterpret_cast<void*>(&km_state), &opt_size);
        
        return km_state;
    }
    
    
    void TestConnect(const int res_connect_expected, const int wait_res_expected)
    {
        sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(5200);
        ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr), 1);
        sockaddr* psa = (sockaddr*)&sa;
        
        ASSERT_NE(srt_bind(m_listener_socket, psa, sizeof sa), SRT_ERROR);
        
        ASSERT_NE(srt_listen(m_listener_socket, 4), SRT_ERROR);
        
        sockaddr_in client_address;
        int length = sizeof(sockaddr_in);
        
        // In non-blocking mode we expect invalid socket returned from srt_accept()
        EXPECT_EQ(srt_accept(m_listener_socket, (sockaddr*)&client_address, &length), SRT_INVALID_SOCK);

        EXPECT_EQ(srt_connect(m_caller_socket, psa, sizeof sa), res_connect_expected);
        
        std::cerr << "srt_connect returned error: " << srt_getlasterror_str() << " (code " << srt_getlasterror(NULL) << ")\n";
        
        int rlen = 2;
        SRTSOCKET read[2];

        int wlen = 2;
        SRTSOCKET write[2];

        const int epoll_res = srt_epoll_wait(m_pollid, read, &rlen,
                                             write, &wlen,
                                             500, /* timeout */
                                             0, 0, 0, 0);
        
        const std::string km_state[] = {
            std::string("SRT_KM_S_UNSECURED (0)"),      //No encryption
            std::string("SRT_KM_S_SECURING  (1)"),      //Stream encrypted, exchanging Keying Material
            std::string("SRT_KM_S_SECURED   (2)"),      //Stream encrypted, keying Material exchanged, decrypting ok.
            std::string("SRT_KM_S_NOSECRET  (3)"),      //Stream encrypted and no secret to decrypt Keying Material
            std::string("SRT_KM_S_BADSECRET (4)")       //Stream encrypted and wrong secret, cannot decrypt Keying Material        
        };
        
        std::cout << "KM State caller: "   << km_state[GetKMState( true)] << '\n';
        std::cout << "KM State listener: " << km_state[GetKMState(false)] << '\n';
        
        const std::string socket_state[] = {
            std::string("SRTS_INVALID"),
            std::string("SRTS_INIT = 1"),
            std::string("SRTS_OPENED"),
            std::string("SRTS_LISTENING"),
            std::string("SRTS_CONNECTING"),
            std::string("SRTS_CONNECTED"),
            std::string("SRTS_BROKEN"),
            std::string("SRTS_CLOSING"),
            std::string("SRTS_CLOSED"),
            std::string("SRTS_NONEXIST")
        };
        
        std::cout << "Caller   state " << socket_state[srt_getsockstate(m_caller_socket)]   << "\n";
        std::cout << "Listener state " << socket_state[srt_getsockstate(m_listener_socket)] << "\n";

        EXPECT_EQ(epoll_res, wait_res_expected);
        if (epoll_res == SRT_ERROR)
        {
            EXPECT_EQ(srt_getlasterror(NULL), MJ_AGAIN * 1000 + MN_XMTIMEOUT);
        }
        
        if (epoll_res == SRT_ERROR)
            std::cerr << "Epoll returned error: " << srt_getlasterror_str() << " (code " << srt_getlasterror(NULL) << '\n';

        std::cerr << "write[0]: " << write[0] << " (listener " << m_listener_socket << ")\n";
        if (res_connect_expected == SRT_SUCCESS)
        {
            EXPECT_EQ(rlen, 0);
            EXPECT_EQ(wlen, 1);
            EXPECT_EQ(write[0], m_listener_socket);
        }
        else
        {
            // The values should not be changed in case of error
            EXPECT_EQ(rlen, 2);
            EXPECT_EQ(wlen, 2);
        }
    }


private:
    // put in any custom data members that you need

    SRTSOCKET m_caller_socket   = SRT_INVALID_SOCK;
    SRTSOCKET m_listener_socket = SRT_INVALID_SOCK;
    
    int       m_pollid          = 0;
    
    const int s_yes = 1;
    const int s_no  = 0;
};



/** 
 * @fn TEST_F(TestStrictEncryption, PasswordLength)
 * @brief The password length should belong to the interval of [10; 80]
 */
TEST_F(TestStrictEncryption, PasswordLength)
{
    // Empty password sets no none
    EXPECT_EQ(SetPassword(std::string(""), true),  SRT_SUCCESS);
    EXPECT_EQ(SetPassword(std::string(""), false), SRT_SUCCESS);
    
    EXPECT_EQ(SetPassword(std::string("too_short"), true),  SRT_ERROR);
    EXPECT_EQ(SetPassword(std::string("too_short"), false), SRT_ERROR);
    
    std::string long_pwd;
    long_pwd.reserve(81);
    for (size_t i = 0; i < 81; ++i)
        long_pwd.push_back(i + 1);
    
    EXPECT_EQ(SetPassword(long_pwd, true),  SRT_ERROR);
    EXPECT_EQ(SetPassword(long_pwd, false), SRT_ERROR);
    
    EXPECT_EQ(SetPassword(std::string("proper_len"),    true),  SRT_SUCCESS);
    EXPECT_EQ(SetPassword(std::string("proper_length"),false),  SRT_SUCCESS);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_Set_Set_Match)
 * @brief Test case #1
 */
TEST_F(TestStrictEncryption, Case_1_Strict_On_On_Pwd_Set_Set_Match)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^t"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_Set_Set_Mismatch)
 * @brief Test case #2
 */
TEST_F(TestStrictEncryption, Case_2_Strict_On_On_Pwd_Set_Set_Mismatch)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^u"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_None_Set)
 * @brief Test case #3.1
 */
TEST_F(TestStrictEncryption, Case_3_1_Strict_On_On_Pwd_None_Set)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string(""), std::string("s!t@r#i$c^u"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_None_Set)
 * @brief Test case #3.2
 */
TEST_F(TestStrictEncryption, Case_3_2_Strict_Off_On_Pwd_None_Set)
{
    SetStrictEncryption(false, true);
    // passwords mismatch
    SetPasswords(std::string(""), std::string("s!t@r#i$c^u"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_Set_None)
 * @brief Test case #4.1
 */
TEST_F(TestStrictEncryption, Case_4_1_Strict_On_On_Pwd_Set_None)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^u"), std::string(""));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_Set_None)
 * @brief Test case #4.2
 */
TEST_F(TestStrictEncryption, Case_4_2_Strict_On_Off_Pwd_Set_None)
{
    SetStrictEncryption(true, false);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^u"), std::string(""));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_None_None)
 * @brief Test case #5.1
 */
TEST_F(TestStrictEncryption, Case_5_1_Strict_On_On_Pwd_None_None)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string(""), std::string(""));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_None_None)
 * @brief Test case #5.2
 */
TEST_F(TestStrictEncryption, Case_5_2_Strict_On_Off_Pwd_None_None)
{
    SetStrictEncryption(true, false);
    // passwords mismatch
    SetPasswords(std::string(""), std::string(""));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_None_None)
 * @brief Test case #5.3
 */
TEST_F(TestStrictEncryption, Case_5_3_Strict_Off_On_Pwd_None_None)
{
    SetStrictEncryption(false, true);
    // passwords mismatch
    SetPasswords(std::string(""), std::string(""));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_None_None)
 * @brief Test case #5.4
 */
TEST_F(TestStrictEncryption, Case_5_4_Strict_Off_Off_Pwd_None_None)
{
    SetStrictEncryption(false, false);
    // passwords mismatch
    SetPasswords(std::string(""), std::string(""));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_Set_Set_Match)
 * @brief Test case #6
 */
TEST_F(TestStrictEncryption, Case_6_Strict_On_Off_Pwd_Set_Set_Match)
{
    SetStrictEncryption(true, false);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^t"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_Set_Set_Mismatch)
 * @brief Test case #7
 */
TEST_F(TestStrictEncryption, Case_7_Strict_On_Off_Pwd_Set_Set_Mismatch)
{
    SetStrictEncryption(true, false);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_None_Set)
 * @brief Test case #8.1
 */
TEST_F(TestStrictEncryption, Case_8_1_Strict_On_Off_Pwd_None_Set)
{
    SetStrictEncryption(true, false);
    // passwords mismatch
    SetPasswords(std::string(""), std::string("s!t@r#i$c^"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_None_Set)
 * @brief Test case #8.2
 */
TEST_F(TestStrictEncryption, Case_8_2_Strict_Off_Off_Pwd_None_Set)
{
    SetStrictEncryption(false, false);
    // passwords mismatch
    SetPasswords(std::string(""), std::string("s!t@r#i$c^"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_Set_Set_Match)
 * @brief Test case #9
 */
TEST_F(TestStrictEncryption, Case_9_Strict_Off_On_Pwd_Set_Set_Match)
{
    SetStrictEncryption(false, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^t"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_Set_Set_Mismatch)
 * @brief Test case #10
 */
TEST_F(TestStrictEncryption, Case_10_Strict_Off_On_Pwd_Set_Set_Mismatch)
{
    SetStrictEncryption(false, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_Set_None)
 * @brief Test case #11.1
 */
TEST_F(TestStrictEncryption, Case_11_1_Strict_Off_On_Pwd_Set_None)
{
    SetStrictEncryption(false, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string(""));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_Set_None)
 * @brief Test case #11.2
 */
TEST_F(TestStrictEncryption, Case_11_2_Strict_Off_Off_Pwd_Set_None)
{
    SetStrictEncryption(false, false);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string(""));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_Set_Set_Match)
 * @brief Test case #12
 */
TEST_F(TestStrictEncryption, Case_12_Strict_Off_Off_Pwd_Set_Set_Match)
{
    SetStrictEncryption(false, false);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^t"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_Set_Set_Mismatch)
 * @brief Test case #13
 */
TEST_F(TestStrictEncryption, Case_13_Strict_Off_Off_Pwd_Set_Set_Mismatch)
{
    SetStrictEncryption(false, false);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c00"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}

