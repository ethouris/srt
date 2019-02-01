#include <vector>
#include <iostream>
#include <thread>
#include "srt-messenger.h"

using namespace std;


const size_t s_message_size = 8 * 1024 * 1024;


void test_messaging_localhost()
{
    const size_t &message_size = s_message_size;
    srt_msngr_listen("srt://:4200?maxconn=4", message_size);

    vector<char> message_rcvd(message_size);
    bool rcv_error = false;

    auto rcv_thread = std::thread([&message_rcvd, &rcv_error, &message_size]
    {
        const int recv_res = srt_msngr_recv(message_rcvd.data(), message_rcvd.size());
        if (recv_res != message_size)
        {
            cerr << "ERROR: Receiving " << message_size << ", received " << recv_res << "\n";
            cerr << srt_msngr_getlasterror_str();
            rcv_error = true;
        }
    });

    // This should block untill we get connected
    srt_msngr_connect("srt://127.0.0.1:4200", message_size);

    // Now we are connected, start sending the message
    vector<char> message_sent(message_size);
    char c = 0;
    for (size_t i = 0; i < message_sent.size(); ++i)
    {
        message_sent[i] = c++;
    }

    const int sent_res = srt_msngr_send(message_sent.data(), message_sent.size());
    if (sent_res != message_size)
    {
        cerr << "ERROR: Sending " << message_size << ", sent " << sent_res << "\n";
        return;
    }

    // Wait for another thread to receive the message (receiving thread)
    rcv_thread.join();

    if (rcv_error)
    {
        // There was an error when receiving. No need to check the message
        return;
    }

    bool mismatch_found = false;
    for (size_t i = 0; i < message_sent.size(); ++i)
    {
        if (message_sent[i] == message_rcvd[i])
            continue;

        mismatch_found = true;
        cerr << "ERROR: Pos " << i
            << " received " << int(message_rcvd[i]) << ", actually sent " << int(message_sent[i]) << "\n";
    }

    if (!mismatch_found)
        cerr << "Check passed\n";

    srt_msngr_destroy();
}


void receive_message(const char *uri)
{
    cout << "Listen to " << uri << "\n";

    const size_t &message_size = s_message_size;
    if (0 != srt_msngr_listen(uri, message_size))
    {
        cerr << "ERROR: Listen failed.\n";

        srt_msngr_destroy();
        return;
    }

    vector<char> message_rcvd(message_size);

    const int recv_res = srt_msngr_recv(message_rcvd.data(), message_rcvd.size());
    if (recv_res <= 0)
    {
        cerr << "ERROR: Receiving message. Result: " << recv_res << "\n";
        cerr << srt_msngr_getlasterror_str();

        srt_msngr_destroy();
        return;
    }

    cout << "RECEIVED MESSAGE:\n";
    cout << string(message_rcvd.data(), message_rcvd.size()).c_str() << endl;
    srt_msngr_destroy();
}


void send_message(const char *uri, const char* message, size_t length)
{
    cout << "Connect to " << uri << "\n";
    const size_t message_size = 8 * 1024 * 1024;
    if (-1 == srt_msngr_connect(uri, message_size))
    {
        cerr << "ERROR: Connect failed.\n";
        srt_msngr_destroy();
        return;
    }

    const int sent_res = srt_msngr_send(message, length);
    if (sent_res != length)
    {
        cerr << "ERROR: Sending message " << length << ". Result: " << sent_res << "\n";
        cerr << srt_msngr_getlasterror_str();
        srt_msngr_destroy();
        return;
    }

    cout << "SENT MESSAGE:\n";
    cout << message << endl;
    srt_msngr_destroy();
}


void print_help()
{
    cout << "The CLI syntax is\n"
         << "    Run autotest: no arguments required\n"
         << "  Two peers test:\n"
         << "    Send:    srt-test-messenger \"srt://ip:port\" \"message\"\n"
         << "    Receive: srt-test-messenger \"srt://ip:port\"\n";
}


void main(int argc, char** argv)
{
    if (argc == 1)
        return test_messaging_localhost();

    // The message part can contain 'help' substring,
    // but it is expected to be in argv[2].
    // So just search for a substring.
    if (nullptr != strstr(argv[1], "help"))
        return print_help();

    if (argc > 3)
    {
        print_help();
        return;
    }


    if (argc == 2)
        return receive_message(argv[1]);

    return send_message(argv[1], argv[2], strnlen(argv[2], s_message_size));

    return;
}

