/*
 * Copyright (c) 2018 <copyright holder> <email>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include <gtest/gtest.h>

#include <thread>
#include <future>

#include "srt.h"




void do_accept_socket(SRTSOCKET listener_socket, int pollid, std::promise<SRTSOCKET> accept_result)
{
    sockaddr_in client_address;
    int length = sizeof(sockaddr_in);
    SRTSOCKET accepted_socket = srt_accept(listener_socket, (sockaddr*)&client_address, &length);
    
//     int rlen = 2;
//     SRTSOCKET read[2];
// 
//     int wlen = 2;
//     SRTSOCKET write[2];
// 
//     const int res = srt_epoll_wait(pollid, read, &rlen,
//                              write, &wlen,
//                              500,
//                              0, 0, 0, 0), SRT_ERROR;
// 
//     ASSERT_EQ(rlen, 1);
//     ASSERT_EQ(read[0], m_client_sock);
    
    
    accept_result.set_value(accepted_socket);  // Notify future
    //accept_result.set_value(SRT_INVALID_SOCK);  // Notify future
}



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
        
        ASSERT_NE(srt_setsockopt(m_caller_socket,   0, SRTO_TSBPDMODE, strict_caller   ? &s_yes : &s_no, sizeof s_yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt(m_listener_socket, 0, SRTO_TSBPDMODE, strict_listener ? &s_yes : &s_no, sizeof s_yes), SRT_ERROR);
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
        
        int rlen = 2;
        SRTSOCKET read[2];

        int wlen = 2;
        SRTSOCKET write[2];

        const int epoll_res = srt_epoll_wait(m_pollid, read, &rlen,
                                             write, &wlen,
                                             500, /* timeout */
                                             0, 0, 0, 0);

        EXPECT_EQ(epoll_res, wait_res_expected);
        if (epoll_res == SRT_ERROR)
        {
            EXPECT_EQ(srt_getlasterror(NULL), MJ_AGAIN * 1000 + MN_XMTIMEOUT);
        }
        
        if (epoll_res == SRT_ERROR)
            std::cerr << srt_getlasterror_str() << '\n';
        
        std::cout << srt_getlasterror(NULL) << '\n';

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


TEST_F(TestStrictEncryption, StrictOnOnPwdMatch)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^t"));
    
    TestConnect(SRT_SUCCESS, 1 /* only one socket epolled*/);
}


TEST_F(TestStrictEncryption, StrictOnOnPwdMismatch)
{
    SetStrictEncryption(true, true);
    // passwords mismatch
    SetPasswords(std::string("s!t@r#i$c^t"), std::string("s!t@r#i$c^u"));
    
    TestConnect(SRT_ERROR, SRT_ERROR);
}




TEST(STRICT_ENCRIPTION, DISABLED_BothPeersSetStrictEnc)
{
    ASSERT_EQ(srt_startup(), 0);

    const int yes = 1;
    const int no = 0;
    
    const char caller_pwd[] = "s!t@r#i$c^t";
    SRTSOCKET caller_socket = srt_create_socket();
    ASSERT_NE(caller_socket, SRT_INVALID_SOCK);

    ASSERT_NE(srt_setsockflag(caller_socket, SRTO_SENDER, &yes, sizeof yes), SRT_ERROR);
    ASSERT_NE(srt_setsockopt (caller_socket, 0, SRTO_RCVSYN,    &yes,  sizeof yes),  SRT_ERROR); // for async connect
    ASSERT_NE(srt_setsockopt (caller_socket, 0, SRTO_SNDSYN,    &yes,  sizeof yes),  SRT_ERROR); // for async connect
    ASSERT_NE(srt_setsockopt (caller_socket, 0, SRTO_TSBPDMODE, &yes, sizeof yes), SRT_ERROR);
    
    // Setting strict encryption values for caller socket
    ASSERT_NE(srt_setsockopt (caller_socket, 0, SRTO_STRICTENC, &yes, sizeof yes), SRT_ERROR);
    ASSERT_NE(srt_setsockopt (caller_socket, 0, SRTO_PASSPHRASE, caller_pwd, sizeof caller_pwd), SRT_ERROR);
    
    
    const char listener_pwd[] = "s!t@r#i$c^u";  // a different password
    //const char listener_pwd[] = "s!t@r#i$c^t";
    SRTSOCKET listener_socket = srt_create_socket();
    ASSERT_NE(listener_socket, SRT_INVALID_SOCK);

    ASSERT_NE(srt_setsockflag(listener_socket, SRTO_SENDER, &no, sizeof no), SRT_ERROR);
    ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_RCVSYN,    &yes,  sizeof yes),  SRT_ERROR); // for async connect
    ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_SNDSYN,    &yes,  sizeof yes),  SRT_ERROR); // for async connect
    ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_TSBPDMODE, &yes, sizeof yes), SRT_ERROR);
    
    // Setting strict encryption values for caller socket
    ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_STRICTENC, &yes, sizeof yes), SRT_ERROR);
    ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_PASSPHRASE, listener_pwd, sizeof listener_pwd), SRT_ERROR);
    
    sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(5200);
    ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr), 1);
    sockaddr* psa = (sockaddr*)&sa;
    
    ASSERT_NE(srt_bind(listener_socket, psa, sizeof sa), SRT_ERROR);
    
    ASSERT_NE(srt_listen(listener_socket, 4), SRT_ERROR);
    
//     sockaddr_in client_address;
//     int length = sizeof(sockaddr_in);
//     SRTSOCKET accepted_socket = srt_accept(listener_socket, (sockaddr*)&client_address, &length);
//     if (accepted_socket == SRT_INVALID_SOCK)
//     {
//         
//     }
    
//     std::promise<SRTSOCKET> accept_result;
//     std::future<SRTSOCKET> accept_result_future = accept_result.get_future();
//     
//     std::thread work_thread(do_accept_socket, listener_socket,
//                             std::move(accept_result));
//     
//     EXPECT_NE(srt_connect(caller_socket, psa, sizeof sa), SRT_ERROR);
//     
//     accept_result_future.wait();  // wait for result
//     std::cout << "result=" << accept_result_future.get() << '\n';
//     EXPECT_EQ(accept_result_future.get(), SRT_ERROR);
//     std::cout << "accept finished \n";
//     work_thread.join();
//     std::cout << "join finished \n";
    
    ASSERT_NE(srt_close(caller_socket), SRT_ERROR);
    ASSERT_NE(srt_close(listener_socket), SRT_ERROR);
    srt_cleanup();
}
