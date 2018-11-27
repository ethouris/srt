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


enum
{
    PEER_CALLER   = 0,
    PEER_LISTENER = 1,
    PEER_COUNT    = 2,  // Number of peers
};


enum TEST_CASE
{
    TEST_CASE_1 = 0,
    TEST_CASE_2,
    TEST_CASE_3_1,
    TEST_CASE_3_2,
    TEST_CASE_4_1,
    TEST_CASE_4_2,
    TEST_CASE_5_1,
    TEST_CASE_5_2,
    TEST_CASE_5_3,
    TEST_CASE_5_4,
    TEST_CASE_6,
    TEST_CASE_7,
    TEST_CASE_8_1,
    TEST_CASE_8_2,
    TEST_CASE_9,
    TEST_CASE_10,
    TEST_CASE_11_1,
    TEST_CASE_11_2,
    TEST_CASE_12,
    TEST_CASE_13,
};


struct TestResult
{
    int     connect_ret;
    int     accept_ret;
    int     epoll_wait_ret;
    int     epoll_wait_error;   // error code set internally by SRT
    int     rnum;               //< set by srt_epoll_wait
    int     wnum;               //< set by srt_epoll_wait
    int     socket_state[PEER_COUNT];
    int     km_state    [PEER_COUNT];
};


struct TestCase
{
    bool            strictenc[PEER_COUNT];
    std::string     password [PEER_COUNT];
    TestResult      expected_result;
};


static const std::string s_pwd_a ("s!t@r#i$c^t");
static const std::string s_pwd_b ("s!t@r#i$c^tu");
static const std::string s_pwd_no("");


static const int SRT_E_TIMEOUT = MJ_AGAIN * 1000 + MN_XMTIMEOUT;
static const int SRT_E_REJECT  = MJ_SETUP * 1000 + MN_RDAVAIL;


/*
 * TESTING SCENARIO
 * Both peers exchange HandShake v5.
 * Listener is sender   in a non-blocking mode
 * Caller   is receiver in a non-blocking mode
 */
const TestCase g_test_matrix[] =
{
        // STRICTENC         |  Password           |                                 EPoll wait                         socket_state                       KM State
        // caller | listener |  caller  | listener |  connect_ret  accept_ret        ret | error             rnum wnum  caller          listener          caller            listener
         { {true,     true  }, {s_pwd_a,   s_pwd_a}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_SECURED,   SRT_KM_S_UNSECURED}}},
         { {true,     true  }, {s_pwd_a,   s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_SECURING,  SRT_KM_S_UNSECURED}}},
/*3.1 */ { {true,     true  }, {s_pwd_no,  s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},
/*3.2 */ { {false,    true  }, {s_pwd_no,  s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},
/*4.1 */ { {true,     true  }, {s_pwd_a,  s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_SECURING,  SRT_KM_S_UNSECURED}}},
/*4.2 */ { {true,    false  }, {s_pwd_a,  s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_NOSECRET,  SRT_KM_S_UNSECURED}}},
/*5.1 */ { {true,     true  }, {s_pwd_no, s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},
/*5.2 */ { {true,    false  }, {s_pwd_no, s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},
/*5.3 */ { {false,    true  }, {s_pwd_no, s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},
/*5.4 */ { {false,   false  }, {s_pwd_no, s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},

/*6   */ { {true,    false  }, {s_pwd_a,   s_pwd_a}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_SECURED,   SRT_KM_S_UNSECURED}}},

/*7   */ { {true,    false  }, {s_pwd_a,   s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_BADSECRET, SRT_KM_S_UNSECURED}}},

/*8.1 */ { {true,    false  }, {s_pwd_no,  s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},
/*8.2 */ { {false,   false  }, {s_pwd_no,  s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_UNSECURED, SRT_KM_S_UNSECURED}}},

/*9   */ { {false,    true  }, {s_pwd_a,   s_pwd_a}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_SECURED,   SRT_KM_S_UNSECURED}}},

/*10  */ { {false,    true  }, {s_pwd_a,   s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_SECURING,  SRT_KM_S_UNSECURED}}},
/*11.1*/ { {false,    true  }, {s_pwd_a,  s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK, -1,  SRT_E_TIMEOUT,   -1,  -1,   {SRTS_BROKEN,    SRTS_LISTENING}, {SRT_KM_S_SECURING,  SRT_KM_S_UNSECURED}}},
/*11.2*/ { {false,   false  }, {s_pwd_a,  s_pwd_no}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_NOSECRET,  SRT_KM_S_UNSECURED}}},
/*12  */ { {false,   false  }, {s_pwd_a,   s_pwd_a}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_SECURED,   SRT_KM_S_UNSECURED}}},
/*13  */ { {false,   false  }, {s_pwd_a,   s_pwd_b}, { SRT_SUCCESS, SRT_INVALID_SOCK,  1,  0,                0,   1,   {SRTS_CONNECTED, SRTS_LISTENING}, {SRT_KM_S_BADSECRET, SRT_KM_S_UNSECURED}}},
};



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

        ASSERT_NE(srt_setsockflag(m_caller_socket,    SRTO_SENDER,    &s_yes, sizeof s_yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt (m_caller_socket, 0, SRTO_RCVSYN,    &s_no,  sizeof s_no),  SRT_ERROR); // non-blocking mode
        ASSERT_NE(srt_setsockopt (m_caller_socket, 0, SRTO_SNDSYN,    &s_no,  sizeof s_no),  SRT_ERROR); // non-blocking mode
        ASSERT_NE(srt_setsockopt (m_caller_socket, 0, SRTO_TSBPDMODE, &s_yes, sizeof s_yes), SRT_ERROR);

        m_listener_socket = srt_create_socket();
        ASSERT_NE(m_listener_socket, SRT_INVALID_SOCK);

        ASSERT_NE(srt_setsockflag(m_listener_socket,    SRTO_SENDER,    &s_no,  sizeof s_no),  SRT_ERROR);
        ASSERT_NE(srt_setsockopt (m_listener_socket, 0, SRTO_RCVSYN,    &s_no,  sizeof s_no),  SRT_ERROR); // non-blocking mode
        ASSERT_NE(srt_setsockopt (m_listener_socket, 0, SRTO_SNDSYN,    &s_no,  sizeof s_no),  SRT_ERROR); // non-blocking mode
        ASSERT_NE(srt_setsockopt (m_listener_socket, 0, SRTO_TSBPDMODE, &s_yes, sizeof s_yes), SRT_ERROR);
        
        // Will use this epoll to wait for srt_accept(...)
        //const int epoll_all = SRT_EPOLL_IN | SRT_EPOLL_OUT | SRT_EPOLL_ERR;
        const int epoll_all = SRT_EPOLL_OUT;
        ASSERT_NE(srt_epoll_add_usock(m_pollid, m_caller_socket, &epoll_all), SRT_ERROR);
    }

    void TearDown()
    {
        // Code here will be called just after the test completes.
        // OK to throw exceptions from here if needed.
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
    
    
    int GetKMState(SRTSOCKET socket)
    {
        int km_state = 0;
        int opt_size = sizeof km_state;
        srt_getsockopt(socket, 0, SRTO_KMSTATE, reinterpret_cast<void*>(&km_state), &opt_size);
        
        return km_state;
    }
    
    
    void TestConnect(TEST_CASE test_no)
    {
        // Prepare input state
        const TestCase &test = g_test_matrix[test_no];
        SetStrictEncryption(test.strictenc[PEER_CALLER], test.strictenc[PEER_LISTENER]);
        SetPasswords       (test.password [PEER_CALLER], test.password [PEER_LISTENER]);
        const TestResult &expect = test.expected_result;
        
        // Start testing
        sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(5200);
        ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr), 1);
        sockaddr* psa = (sockaddr*)&sa;
        
        ASSERT_NE(srt_bind  (m_listener_socket, psa, sizeof sa), SRT_ERROR);
        ASSERT_NE(srt_listen(m_listener_socket, 4),              SRT_ERROR);
        
        sockaddr_in client_address;
        int length = sizeof(sockaddr_in);
        
        // In non-blocking mode we expect invalid socket returned from srt_accept()
        EXPECT_EQ(srt_accept(m_listener_socket, (sockaddr*)&client_address, &length), expect.accept_ret);

        const int connect_ret = srt_connect(m_caller_socket, psa, sizeof sa);
        EXPECT_EQ(connect_ret, expect.connect_ret);
        
        if (connect_ret == SRT_ERROR && connect_ret != expect.connect_ret)
        {
            std::cerr << s_sh_bpurple << "UNEXPECTED! srt_connect returned error: " << s_sh_nocolor
                      << srt_getlasterror_str() << " (code " << srt_getlasterror(NULL) << ")\n";
        }
        
        const int default_len = 3;
        int rlen = default_len;
        SRTSOCKET read[default_len];

        int wlen = default_len;
        SRTSOCKET write[default_len];

        const int epoll_res = srt_epoll_wait(m_pollid, read, &rlen,
                                             write, &wlen,
                                             500, /* timeout */
                                             0, 0, 0, 0);
        
        EXPECT_EQ(epoll_res, expect.epoll_wait_ret);
        if (epoll_res == SRT_ERROR)
        {
            EXPECT_EQ(srt_getlasterror(NULL), expect.epoll_wait_error);
            std::cerr << "Epoll returned error: " << srt_getlasterror_str() << " (code " << srt_getlasterror(NULL) << '\n';
        }
        
        if (m_is_tracing)
        {
            std::cout << m_sh_bcyan;
            std::cout << "Socket state caller:   " << m_socket_state[srt_getsockstate(m_caller_socket)]   << "\n";
            std::cout << "Socket state listener: " << m_socket_state[srt_getsockstate(m_listener_socket)] << "\n";
            
            std::cout << "KM State caller:       " << m_km_state[GetKMState(m_caller_socket)] << '\n';
            std::cout << "KM State listener:     " << m_km_state[GetKMState(m_listener_socket)] << '\n';
            
            std::cout << "wlen: " << wlen << " (write[0] " << write[0] << ", listener " << m_listener_socket << ")\n";
            std::cout << "rlen: " << rlen << " (read[0]  " << read[0]  << ", caller "   << m_caller_socket << ")\n";
            std::cout << s_sh_nocolor;
        }
        
        EXPECT_EQ(srt_getsockstate(m_caller_socket),   expect.socket_state[PEER_CALLER]);
        EXPECT_EQ(srt_getsockstate(m_listener_socket), expect.socket_state[PEER_LISTENER]);
        EXPECT_EQ(GetKMState(m_caller_socket),         expect.km_state[PEER_CALLER]);
        EXPECT_EQ(GetKMState(m_listener_socket),       expect.km_state[PEER_LISTENER]);
        
        EXPECT_EQ(rlen, expect.rnum >= 0 ? expect.rnum : default_len);
        EXPECT_EQ(wlen, expect.wnum >= 0 ? expect.wnum : default_len);
        if (rlen != 0 && rlen != 3)
        {
            EXPECT_EQ(read[0],  m_caller_socket);
        }
        if (wlen != 0 && wlen != 3)
        {
            EXPECT_EQ(write[0], m_caller_socket);
        }

    }


private:
    // put in any custom data members that you need

    SRTSOCKET m_caller_socket   = SRT_INVALID_SOCK;
    SRTSOCKET m_listener_socket = SRT_INVALID_SOCK;
    
    int       m_pollid          = 0;
    
    const int s_yes = 1;
    const int s_no  = 0;
    
    const char* s_sh_bpurple = "\033[1;35m";      // Bold Purple
    const char* m_sh_bcyan   = "\033[1;36m";
    const char* s_sh_red     = "\033[0;31m";
    const char* s_sh_nocolor = "\033[0m"; // No Color
    
    const bool          m_is_tracing = true;
    static const char*  m_km_state[];
    static const char*  m_socket_state[];
};



const char* TestStrictEncryption::m_km_state[] = {
    "SRT_KM_S_UNSECURED (0)",      //No encryption
    "SRT_KM_S_SECURING  (1)",      //Stream encrypted, exchanging Keying Material
    "SRT_KM_S_SECURED   (2)",      //Stream encrypted, keying Material exchanged, decrypting ok.
    "SRT_KM_S_NOSECRET  (3)",      //Stream encrypted and no secret to decrypt Keying Material
    "SRT_KM_S_BADSECRET (4)"       //Stream encrypted and wrong secret, cannot decrypt Keying Material        
};


const char* TestStrictEncryption::m_socket_state[] = {
    "SRTS_INVALID",
    "SRTS_INIT = 1",
    "SRTS_OPENED",
    "SRTS_LISTENING",
    "SRTS_CONNECTING",
    "SRTS_CONNECTED",
    "SRTS_BROKEN",
    "SRTS_CLOSING",
    "SRTS_CLOSED",
    "SRTS_NONEXIST"
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
    TestConnect(TEST_CASE_1);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_Set_Set_Mismatch)
 * @brief Test case #2
 */
TEST_F(TestStrictEncryption, Case_2_Strict_On_On_Pwd_Set_Set_Mismatch)
{
    TestConnect(TEST_CASE_2);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_None_Set)
 * @brief Test case #3.1
 */
TEST_F(TestStrictEncryption, Case_3_1_Strict_On_On_Pwd_None_Set)
{
    TestConnect(TEST_CASE_3_1);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_None_Set)
 * @brief Test case #3.2
 */
TEST_F(TestStrictEncryption, Case_3_2_Strict_Off_On_Pwd_None_Set)
{
    TestConnect(TEST_CASE_3_2);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_Set_None)
 * @brief Test case #4.1
 */
TEST_F(TestStrictEncryption, Case_4_1_Strict_On_On_Pwd_Set_None)
{
    TestConnect(TEST_CASE_4_1);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_Set_None)
 * @brief Test case #4.2
 */
TEST_F(TestStrictEncryption, Case_4_2_Strict_On_Off_Pwd_Set_None)
{
    TestConnect(TEST_CASE_4_2);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_On_Pwd_None_None)
 * @brief Test case #5.1
 */
TEST_F(TestStrictEncryption, Case_5_1_Strict_On_On_Pwd_None_None)
{
    TestConnect(TEST_CASE_5_1);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_None_None)
 * @brief Test case #5.2
 */
TEST_F(TestStrictEncryption, Case_5_2_Strict_On_Off_Pwd_None_None)
{
    TestConnect(TEST_CASE_5_2);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_None_None)
 * @brief Test case #5.3
 */
TEST_F(TestStrictEncryption, Case_5_3_Strict_Off_On_Pwd_None_None)
{
    TestConnect(TEST_CASE_5_3);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_None_None)
 * @brief Test case #5.4
 */
TEST_F(TestStrictEncryption, Case_5_4_Strict_Off_Off_Pwd_None_None)
{
    TestConnect(TEST_CASE_5_4);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_Set_Set_Match)
 * @brief Test case #6
 */
TEST_F(TestStrictEncryption, Case_6_Strict_On_Off_Pwd_Set_Set_Match)
{
    TestConnect(TEST_CASE_6);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_Set_Set_Mismatch)
 * @brief Test case #7
 */
TEST_F(TestStrictEncryption, Case_7_Strict_On_Off_Pwd_Set_Set_Mismatch)
{
    TestConnect(TEST_CASE_7);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_On_Off_Pwd_None_Set)
 * @brief Test case #8.1
 */
TEST_F(TestStrictEncryption, Case_8_1_Strict_On_Off_Pwd_None_Set)
{
    TestConnect(TEST_CASE_8_1);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_None_Set)
 * @brief Test case #8.2
 */
TEST_F(TestStrictEncryption, Case_8_2_Strict_Off_Off_Pwd_None_Set)
{
    TestConnect(TEST_CASE_8_2);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_Set_Set_Match)
 * @brief Test case #9
 */
TEST_F(TestStrictEncryption, Case_9_Strict_Off_On_Pwd_Set_Set_Match)
{
    TestConnect(TEST_CASE_9);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_Set_Set_Mismatch)
 * @brief Test case #10
 */
TEST_F(TestStrictEncryption, Case_10_Strict_Off_On_Pwd_Set_Set_Mismatch)
{
    TestConnect(TEST_CASE_10);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_On_Pwd_Set_None)
 * @brief Test case #11.1
 */
TEST_F(TestStrictEncryption, Case_11_1_Strict_Off_On_Pwd_Set_None)
{
    TestConnect(TEST_CASE_11_1);
}



/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_Set_None)
 * @brief Test case #11.2
 */
TEST_F(TestStrictEncryption, Case_11_2_Strict_Off_Off_Pwd_Set_None)
{
    TestConnect(TEST_CASE_11_2);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_Set_Set_Match)
 * @brief Test case #12
 */
TEST_F(TestStrictEncryption, Case_12_Strict_Off_Off_Pwd_Set_Set_Match)
{
    TestConnect(TEST_CASE_12);
}


/** 
 * @fn TEST_F(TestStrictEncryption, Strict_Off_Off_Pwd_Set_Set_Mismatch)
 * @brief Test case #13
 */
TEST_F(TestStrictEncryption, Case_13_Strict_Off_Off_Pwd_Set_Set_Mismatch)
{
    TestConnect(TEST_CASE_13);
}

