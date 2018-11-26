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



class TestStrictEncryption
    : public ::testing::test
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
        
        const int yes = 1;
        const int no = 0;
        
        SRTSOCKET m_caller_socket = srt_create_socket();
        ASSERT_NE(m_caller_socket, SRT_INVALID_SOCK);

        ASSERT_NE(srt_setsockflag(m_caller_socket, SRTO_SENDER, &yes, sizeof yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_RCVSYN,    &yes,  sizeof yes),  SRT_ERROR);       // for async connect
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_SNDSYN,    &yes,  sizeof yes),  SRT_ERROR);       // for async connect
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_TSBPDMODE, &yes, sizeof yes), SRT_ERROR);

        // Setting strict encryption values for caller socket
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_STRICTENC, &yes, sizeof yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt(m_caller_socket, 0, SRTO_PASSPHRASE, caller_pwd, sizeof caller_pwd), SRT_ERROR);
        
        SRTSOCKET listener_socket = srt_create_socket();
        ASSERT_NE(listener_socket, SRT_INVALID_SOCK);

        ASSERT_NE(srt_setsockflag(listener_socket, SRTO_SENDER, &no, sizeof no), SRT_ERROR);
        ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_RCVSYN,    &yes,  sizeof yes),  SRT_ERROR); // for async connect
        ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_SNDSYN,    &yes,  sizeof yes),  SRT_ERROR); // for async connect
        ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_TSBPDMODE, &yes, sizeof yes), SRT_ERROR);
        
        // Setting strict encryption values for caller socket
        ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_STRICTENC, &yes, sizeof yes), SRT_ERROR);
        ASSERT_NE(srt_setsockopt (listener_socket, 0, SRTO_PASSPHRASE, listener_pwd, sizeof listener_pwd), SRT_ERROR);
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
    
    
    void SetStrictEncryption(bool strict_caller, bool strict_listener);


private:
    // put in any custom data members that you need

    SRTSOCKET m_caller_socket   = SRT_INVALID_SOCK;
    SRTSOCKET m_listener_socket = SRT_INVALID_SOCK;
};



void do_accept_socket(SRTSOCKET listener_socket, std::promise<SRTSOCKET> accept_result)
{
//     sockaddr_in client_address;
//     int length = sizeof(sockaddr_in);
//     SRTSOCKET accepted_socket = srt_accept(listener_socket, (sockaddr*)&client_address, &length);
    
    //accept_result.set_value(accepted_socket);  // Notify future
    accept_result.set_value(SRT_INVALID_SOCK);  // Notify future
}


TEST(STRICT_ENCRIPTION, BothPeersSetStrictEnc)
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
    
    std::promise<SRTSOCKET> accept_result;
    std::future<SRTSOCKET> accept_result_future = accept_result.get_future();
    
    std::thread work_thread(do_accept_socket, listener_socket,
                            std::move(accept_result));
    
    EXPECT_NE(srt_connect(caller_socket, psa, sizeof sa), SRT_ERROR);
    
    accept_result_future.wait();  // wait for result
    std::cout << "result=" << accept_result_future.get() << '\n';
    work_thread.join();
    
    ASSERT_NE(srt_close(caller_socket), SRT_ERROR);
    ASSERT_NE(srt_close(listener_socket), SRT_ERROR);
    srt_cleanup();
}
