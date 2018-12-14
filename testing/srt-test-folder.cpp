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

#ifdef _WIN32
#include <direct.h>
#include "dirent.h"
#else
#include <dirent.h>
#endif

#include <iostream>
#include <iterator>
#include <vector>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <srt.h>
#include <udt.h>

#include "apputil.hpp"
#include "uriparser.hpp"
#include "logsupport.hpp"
#include "socketoptions.hpp"
#include "verbose.hpp"
#include "testmedia.hpp"

#ifndef S_ISDIR
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif

bool Upload(UriParser& srt, UriParser& file);
bool Download(UriParser& srt, UriParser& file);

const logging::LogFA SRT_LOGFA_APP = 10;

static size_t g_buffer_size = 1024 * 1024;  // !MB
static bool g_skip_flushing = false;

using namespace std;

int main( int argc, char** argv )
{
    set<string>
        o_loglevel = { "ll", "loglevel" },
        o_buffer   = {"b", "buffer" },
        o_verbose  = {"v", "verbose" },
        o_noflush  = {"s", "skipflush" };

    // Options that expect no arguments (ARG_NONE) need not be mentioned.
    vector<OptionScheme> optargs = {
        { o_loglevel, OptionScheme::ARG_ONE },
        { o_buffer, OptionScheme::ARG_ONE }
    };
    options_t params = ProcessOptions(argv, argc, optargs);

    /*
    cerr << "OPTIONS (DEBUG)\n";
    for (auto o: params)
    {
        cerr << "[" << o.first << "] ";
        copy(o.second.begin(), o.second.end(), ostream_iterator<string>(cerr, " "));
        cerr << endl;
    }
    */

    vector<string> args = params[""];
    if ( args.size() < 2 )
    {
        cerr << "Usage: " << argv[0] << " <source> <target>\n";
        cerr << "Example (receiver):\n   " << argv[0] << " srt://:4200 file://.\n";
        cerr << "   will receive the streaming on port 4200 of the localhost and wtire to the current forder.\n";
        cerr << "Example (sender):\n   " << argv[0] << "file://folder_to_send srt://192.168.0.102:4200\n";
        cerr << "   will send the contents of the folder_to_send on port 4200 of the 192.168.0.102.\n";
        cerr << "Example (sender with bandwidth limit):\n   " << argv[0] << "file://folder_to_send srt://192.168.0.102:4200?maxbw=625000\n";
        cerr << "   will send the contents of the folder_to_send on port 4200 of the 192.168.0.102\n";
        cerr << "   with a bitrate limit of 5 Mbps (625000 bytes/s).\n";

        return 1;
    }

    string loglevel = Option<OutString>(params, "error", o_loglevel);
    logging::LogLevel::type lev = SrtParseLogLevel(loglevel);
    UDT::setloglevel(lev);
    UDT::addlogfa(SRT_LOGFA_APP);

   string verbo = Option<OutString>(params, "no", o_verbose);
   if ( verbo == "" || !false_names.count(verbo) )
       Verbose::on = true;

    string bs = Option<OutString>(params, "", o_buffer);
    if ( bs != "" )
    {
        ::g_buffer_size = stoi(bs);
    }

    string sf = Option<OutString>(params, "no", o_noflush);
    if (sf == "" || !false_names.count(sf))
        ::g_skip_flushing = true;

    string source = args[0];
    string target = args[1];

    UriParser us(source), ut(target);

    Verb() << "SOURCE type=" << us.scheme() << ", TARGET type=" << ut.scheme();

    try
    {
        if (us.scheme() == "srt")
        {
            if (ut.scheme() != "file")
            {
                cerr << "SRT to FILE should be specified\n";
                return 1;
            }
            Download(us, ut);
        }
        else if (ut.scheme() == "srt")
        {
            if (us.scheme() != "file")
            {
                cerr << "FILE to SRT should be specified\n";
                return 1;
            }
            Upload(ut, us);
        }
        else
        {
            cerr << "SRT URI must be one of given media.\n";
            return 1;
        }
    }
    catch (std::exception& x)
    {
        cerr << "ERROR: " << x.what() << endl;
        return 1;
    }


    return 0;
}

void ExtractPath(string path, ref_t<string> dir, ref_t<string> fname)
{
    string directory = path;
    string filename = "";

    struct stat state;
    stat(path.c_str(), &state);
    if (!S_ISDIR(state.st_mode))
    {
        // Extract directory as a butlast part of path
        size_t pos = path.find_last_of("/");
        if ( pos == string::npos )
        {
            filename = path;
            directory = ".";
        }
        else
        {
            directory = path.substr(0, pos);
            filename = path.substr(pos+1);
        }
    }

    if (directory[0] != '/')
    {
        // Glue in the absolute prefix of the current directory
        // to make it absolute. This is needed to properly interpret
        // the fixed uri.
        static const size_t s_max_path = 4096; // don't care how proper this is
        char tmppath[s_max_path];
        char* gwd = getcwd(tmppath, s_max_path);
        if ( !gwd )
        {
            // Don't bother with that now. We need something better for that anyway.
            throw std::invalid_argument("Path too long");
        }
        string wd = gwd;

        directory = wd + "/" + directory;
    }

    *dir = directory;
    *fname = filename;
}



bool TransmitFile(const char* filename, const SRTSOCKET ss, vector<char> &buf)
{
    ifstream ifile(filename, ios::binary);
    if (!ifile)
    {
        cerr << "Error opening file: '" << filename << "'";
        return true;
    }

    Verb() << "Transmitting '" << filename;

    /* 1 byte     string    1 byte
     * ------------------------------------------------
     * | is_eof | Filename | 0 | Payload
     * ------------------------------------------------
     * We add +2 to include the first byte and the \0-character
     */
    int hdr_size = snprintf(buf.data() + 1, buf.size(), "%s", filename) + 2;

    for (;;)
    {
        int n = ifile.read(buf.data() + hdr_size, buf.size() - hdr_size).gcount();
        const bool is_eof = ifile.eof();
        const bool is_start = hdr_size > 1;
        buf[0] = (is_eof ? 2 : 0) | (is_start ? 1 : 0);

        size_t shift = 0;
        if (n > 0)
        {
            int st = srt_send(ss, buf.data() + shift, n + hdr_size);
            //Verb() << "Upload: " << n << " + " << hdr_size << " (" << (n + hdr_size) << ")  --> " << st << (!shift ? string() : "+" + Sprint(shift));
            if (st == SRT_ERROR)
            {
                cerr << "Upload: SRT error: " << srt_getlasterror_str() << endl;
                return false;
            }

            n -= st - hdr_size;
            shift += st - hdr_size;
            hdr_size = 1;
            if (n != 0) {
                cerr << "Upload error: not full delivery" << endl;
                return false;
            }
        }

        if (is_eof)
            break;

        if (!ifile.good())
        {
            cerr << "ERROR while reading file\n";
            return false;
        }
    }

    Verb() << "---> done!";

    return true;
}


bool DoUpload(UriParser& ut, string path)
{
    ut["transtype"] = string("file");
    ut["messageapi"] = string("true");
    ut["sndbuf"] = to_string(1061313/*g_buffer_size*/ /* 1456*/);
    SrtModel m(ut.host(), ut.portno(), ut.parameters());

    string dummy;
    m.Establish(Ref(dummy));

    SRTSOCKET ss = m.Socket();

    /* Scan files in directory */
    struct dirent **files;
    const int n = scandir(path.c_str(), &files, NULL, alphasort);
    if (n < 0)
    {
        cerr << "No files found in the directory: '" << path << "'";
        return false;
    }

    // Use a manual loop for reading from SRT
    vector<char> buf(::g_buffer_size);
    bool send_next = true;

    for (int i = 0; i < n; ++i)
    {
        struct dirent *ent = files[i];
        if (ent->d_type != DT_REG)
        {
            free(files[i]);
            continue;
        }

        // On error we will skip transfering and free all the handles.
        if (send_next)
            send_next = TransmitFile(ent->d_name, ss, buf);

        free(files[i]);
    }

    free(files);

    return true;
}


bool DoDownload(UriParser& us, string directory)
{
    us["transtype"] = string("file");
    us["messageapi"] = string("true");
    us["rcvbuf"] = to_string(2 * 1061312 + 1472/*g_buffer_size*/ /* 1456*/);
    SrtModel m(us.host(), us.portno(), us.parameters());

    string dummy;
    m.Establish(Ref(dummy));

    // Disregard the filename, unless the destination file exists.

    string path = directory + "/";
    struct stat state;
    if (stat(path.c_str(), &state) == -1)
    {
        switch ( errno )
        {
        case ENOENT:
            // This is expected, go on.
            break;

        default:
            cerr << "Download: error '" << errno << "'when checking destination location: " << path << endl;
            return false;
        }
    }
    else
    {
        // Check if destination is a regular file, if so, allow to overwrite.
        // Otherwise reject.
        if (!S_ISDIR(state.st_mode))
        {
            cerr << "Download: target location '" << path << "' does not designate a folder.\n";
            return false;
        }
    }

    SRTSOCKET ss = m.Socket();
    Verb() << "Downloading from '" << us.uri() << "' to '" << path;

    vector<char> buf(::g_buffer_size);

    ofstream ofile;
    for (;;)
    {
        const int n = srt_recv(ss, buf.data(), ::g_buffer_size);
        if (n == SRT_ERROR)
        {
            cerr << "Download: SRT error: " << srt_getlasterror_str() << endl;
            return false;
        }

        if (n == 0)
        {
            Verb() << "Nothig was received. Closing.";
            break;
        }

        int hdr_size = 1;
        const bool is_first = (buf[0] & 0x01) != 0;
        const bool is_eof   = (buf[0] & 0x02) != 0;

        if (is_first)
        {
            ofile.close();
            // extranct the filename from the received buffer
            string filename = string(buf.data() + 1);
            hdr_size += filename.size() + 1;    // 1 for null character
            ofile.open(filename.c_str(), ios::out | ios::trunc | ios::binary);
            if (!ofile) {
                cerr << "Download: error opening file" << filename << endl;
                break;
            }

            Verb() << "Downloading: --> " << filename;
        }

        //Verb() << "Received " << n << " bytes";
        ofile.write(buf.data() + hdr_size, n - hdr_size);

        if (is_eof)
        {
            ofile.close();
            Verb() << "--> done\n";
        }
    }

    return true;
}

bool Upload(UriParser& srt_target_uri, UriParser& fileuri)
{
    if (fileuri.scheme() != "file")
    {
        cerr << "Upload: source accepted only as a folder\n";
        return false;
    }

    string path = fileuri.path();
    string directory, filename;
    ExtractPath(path, ref(directory), ref(filename));

    if (!filename.empty())
    {
        cerr << "Upload: source accepted only as a folder (file "
             << filename << " is specified)\n";
        return false;
    }

    Verb() << "Extract path '" << path << "': directory=" << directory;
    
    // Add some extra parameters.
    srt_target_uri["transtype"] = "file";

    return DoUpload(srt_target_uri, path);
}

bool Download(UriParser& srt_source_uri, UriParser& fileuri)
{
    if (fileuri.scheme() != "file" )
    {
        cerr << "Download: target accepted only as a folder\n";
        return false;
    }

    string path = fileuri.path(), directory, filename;
    ExtractPath(path, Ref(directory), Ref(filename));

    srt_source_uri["transtype"] = "file";

    return DoDownload(srt_source_uri, directory);
}

