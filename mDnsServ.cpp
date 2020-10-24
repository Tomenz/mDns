/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

// http://www.dns-sd.org/servicetypes.html
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt


#include <iostream>
#include <iomanip>
#include <sstream>
#include <regex>
#include <algorithm>
#include <random>
#include <condition_variable>
#include <map>
#include <atomic>

#include "socketlib/SocketLib.h"
#include "DnsProtokol.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Ws2tcpip.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "x64/Debug/socketlib64d")
#else
#pragma comment(lib, "Debug/socketlib32d")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "x64/Release/socketlib64")
#else
#pragma comment(lib, "Release/socketlib32")
#endif
#endif
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#endif

using namespace std::placeholders;

class RandIntervalTimer
{
public:

    RandIntervalTimer()
    {
    }

    virtual ~RandIntervalTimer()
    {
        Stop();
    }

    template<typename fn, typename... Args>
    void Start(fn f, Args... args)
    {
        m_thWaitThread = thread([&](fn&& f1, Args&&... args1)
        {
            atomic_init(&m_bStop, false);
            function<typename result_of<fn(Args...)>::type()> task(bind(forward<fn>(f1), forward<Args>(args1)...));
            uniform_int_distribution<int> dist(5000, 10000);

            unique_lock<mutex> lock(mut);

            do
            {
                random_device rd;
                mt19937 mt(rd());
                int tMilliSeconds = dist(mt);

//              { const auto tNow = chrono::system_clock::to_time_t(chrono::system_clock::now());  wstringstream ss; ss << put_time(::localtime(&tNow)), L"%a, %d %b %Y %H:%M:%S") << L" - Timer starts mit: " << tMilliSeconds << L" Millisekunden\r\n";  OutputDebugString(ss.str().c_str()); }
                m_cv.wait_for(lock, chrono::milliseconds(tMilliSeconds));
                if (m_bStop == false)
                {
                    task();
//                  OutputDebugString(L"Timer Callback aufgerufen\r\n");
                }
                dist = uniform_int_distribution<int>(10000, 100000);
            } while (m_bStop == false);
        }, forward<fn>(f), forward<Args>(args)...);
    }

    void Stop()
    {
        mut.lock();
        m_bStop = true;
        m_cv.notify_all();
        mut.unlock();

        if (m_thWaitThread.joinable() == true)
            m_thWaitThread.join();
    }

private:
    thread m_thWaitThread;
    atomic<bool> m_bStop;
    mutex mut;
    condition_variable m_cv;
};

class mDnsServer
{
public:
    mDnsServer()
    {
    }

    ~mDnsServer()
    {
    }

    void Start()
    {
        BaseSocket::EnumIpAddresses([&](int adrFamily, const string& strIpAddr, int nInterfaceIndex, void*) -> int
        {
            wcout << strIpAddr.c_str() << endl;//OutputDebugStringA(strIpAddr.c_str()); OutputDebugStringA("\r\n");

            pair<map<unique_ptr<UdpSocket>, tuple<int, string, uint32_t>>::iterator, bool>paRet = m_maSockets.emplace(make_unique<UdpSocket>(), make_tuple(adrFamily, strIpAddr, nInterfaceIndex));
            if (paRet.second == true)
            {
                paRet.first->first->BindErrorFunction(static_cast<function<void(BaseSocket* const)>>(bind(&mDnsServer::SocketError, this, _1)));
                paRet.first->first->BindCloseFunction(static_cast<function<void(BaseSocket* const)>>(bind(&mDnsServer::SocketCloseing, this, _1)));
                paRet.first->first->BindFuncBytesReceived(static_cast<function<void(UdpSocket* const)>>(bind(&mDnsServer::DatenEmpfangen, this, _1)));
                if (get<0>(paRet.first->second) == AF_INET)
                {
                    if (paRet.first->first->Create(strIpAddr.c_str(), 5353, "0.0.0.0") == false)
                        wcout << L"Error creating Socket: " << strIpAddr.c_str() << endl;
                    if (paRet.first->first->AddToMulticastGroup("224.0.0.251", strIpAddr.c_str(), nInterfaceIndex) == false)
                        wcout << L"Error joining Multicastgroup: " << strIpAddr.c_str() << endl;
                }
                else if (get<0>(paRet.first->second) == AF_INET6)
                {
                    if (paRet.first->first->Create(strIpAddr.c_str(), 5353, "::") == false)
                        wcout << L"Error creating Socket: " << strIpAddr.c_str() << endl;
                    if (paRet.first->first->AddToMulticastGroup("FF02::FB", strIpAddr.c_str(), nInterfaceIndex) == false)
                        wcout << L"Error joining Multicastgroup: " << strIpAddr.c_str() << endl;
                }
            }

            return 0;
        }, 0);

        // https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
        for (const auto& item : m_maSockets)
        {
            //if (item.second.first == AF_INET6)
            {
                m_maTimer.emplace(new RandIntervalTimer(), make_pair(item.first.get(), "_services._dns-sd._udp.local"));
                m_maTimer.emplace(new RandIntervalTimer(), make_pair(item.first.get(), "_benzinger._tcp.local"));
            }
        }
        for (auto& item : m_maTimer)
            item.first->Start(&mDnsServer::SendSrvSearch, this, item.second.second, item.second.first);

//        SendSrvSearch("b._dns - sd._udp.local");
//        SendSrvSearch("db._dns - sd._udp.local");
//        SendSrvSearch("r._dns - sd._udp.local");
//        SendSrvSearch("dr._dns - sd._udp.local");
//        SendSrvSearch("lb._dns - sd._udp.local");
    }

    void Stop()
    {
        while (m_maTimer.size())
        {
            delete m_maTimer.begin()->first;
            m_maTimer.erase(m_maTimer.begin());
        }

        while (m_maSockets.size())
        {
            if (get<0>(m_maSockets.begin()->second) == AF_INET)
            {
                if (m_maSockets.begin()->first->RemoveFromMulticastGroup("224.0.0.251", get<1>(m_maSockets.begin()->second).c_str(), get<2>(m_maSockets.begin()->second)) == false)
                    wcout << L"Error leaving Multicastgroup: " << get<1>(m_maSockets.begin()->second).c_str() << endl;
            }
            else if (get<0>(m_maSockets.begin()->second) == AF_INET6)
            {
                if (m_maSockets.begin()->first->RemoveFromMulticastGroup("FF02::FB", get<1>(m_maSockets.begin()->second).c_str(), get<2>(m_maSockets.begin()->second)) == false)
                    wcout << L"Error leaving Multicastgroup: " << get<1>(m_maSockets.begin()->second).c_str() << endl;
            }
            m_maSockets.begin()->first->Close();
            m_maSockets.erase(m_maSockets.begin());
        }
    }


    void SocketError(BaseSocket* pBaseSocket)
    {
        wcout << L"Error in Verbindung" << endl;
        pBaseSocket->Close();
    }

    void SocketCloseing(BaseSocket* pBaseSocket)
    {
        wcout << L"Socket closing" << endl;
    }

    void DatenEmpfangen(UdpSocket* pUdpSocket)
    {
        size_t nAvalible = pUdpSocket->GetBytesAvailible();

        auto spBuffer = make_unique<unsigned char[]>(nAvalible + 1);

        string strFrom;
        size_t nRead = pUdpSocket->Read(spBuffer.get(), nAvalible, strFrom);

        if (nRead > 0 && nRead < 9999)
        {
            DnsProtokol dnsProto(spBuffer.get(), nRead);

            wstringstream strOutput;
            const auto tNow = chrono::system_clock::to_time_t(chrono::system_clock::now());
            const auto& pItem = find_if(begin(m_maSockets), end(m_maSockets), [&pUdpSocket](const auto& it) { return it.first.get() == pUdpSocket; });
            strOutput << put_time(localtime(&tNow), L"%a, %d %b %Y %H:%M:%S") << " - ";
            strOutput << strFrom.c_str() << L" on Interface: " << (pItem != end(m_maSockets) ? get<1>(pItem->second).c_str() : "") << endl;

            if (dnsProto.m_strLastErrMsg.empty() == true)
            {
                strOutput << L"ID: " << dnsProto.m_DnsHeader.ID << L", AA: " << dnsProto.m_DnsHeader.AA << L", OPCODE: " << dnsProto.m_DnsHeader.Opcode << L", QR: " << dnsProto.m_DnsHeader.QR << L", RA: " << dnsProto.m_DnsHeader.RA << L", RCODE: " << dnsProto.m_DnsHeader.RCODE << L", RD: " << dnsProto.m_DnsHeader.RD << L", TC: " << dnsProto.m_DnsHeader.TC << L", Z: " << dnsProto.m_DnsHeader.Z << endl;
                strOutput << L"hat " << dnsProto.m_DnsHeader.QDCOUNT << L" fragen, " << dnsProto.m_DnsHeader.ANCOUNT << L" RRs Antworten, " << dnsProto.m_DnsHeader.NSCOUNT << L" NS Antworten, " << dnsProto.m_DnsHeader.ARCOUNT << L" AR Antworten" << endl;

                for (short n = 0; n < dnsProto.m_DnsHeader.QDCOUNT; ++n)
                    strOutput << dnsProto.m_pQuestions.get()[n].LABEL.c_str() << L" -> QTYPE: " << dnsProto.m_pQuestions.get()[n].QTYPE << L" -> QCLASS: " << dnsProto.m_pQuestions.get()[n].QCLASS << endl;

                for (short n = 0; n < dnsProto.m_DnsHeader.ANCOUNT; ++n)
                    strOutput << dnsProto.m_pAnswers.get()[n].LABEL.c_str() << L" -> TYPE: " << dnsProto.m_pAnswers.get()[n].TYPE << L" -> CLASS: " << dnsProto.m_pAnswers.get()[n].CLASS << L" -> TTL: " << dnsProto.m_pAnswers.get()[n].TTL << L" -> RDLENGTH: " << dnsProto.m_pAnswers.get()[n].RDLENGTH << L" -> RDATA: " << dnsProto.m_pAnswers.get()[n].RDATA.c_str() << endl;

                for (short n = 0; n < dnsProto.m_DnsHeader.NSCOUNT; ++n)
                    strOutput << dnsProto.m_pNameServ.get()[n].LABEL.c_str() << L" -> TYPE: " << dnsProto.m_pNameServ.get()[n].TYPE << L" -> CLASS: " << dnsProto.m_pNameServ.get()[n].CLASS << L" -> TTL: " << dnsProto.m_pNameServ.get()[n].TTL << L" -> RDLENGTH: " << dnsProto.m_pNameServ.get()[n].RDLENGTH << L" -> RDATA: " << dnsProto.m_pNameServ.get()[n].RDATA.c_str() << endl;

                for (short n = 0; n < dnsProto.m_DnsHeader.ARCOUNT; ++n)
                    strOutput << dnsProto.m_pExtraRec.get()[n].LABEL.c_str() << L" -> TYPE: " << dnsProto.m_pExtraRec.get()[n].TYPE << L" -> CLASS: " << dnsProto.m_pExtraRec.get()[n].CLASS << L" -> TTL: " << dnsProto.m_pExtraRec.get()[n].TTL << L" -> RDLENGTH: " << dnsProto.m_pExtraRec.get()[n].RDLENGTH << L" -> RDATA: " << dnsProto.m_pExtraRec.get()[n].RDATA.c_str() << endl;

                if (dnsProto.m_nBytesDecodet != nRead)
                    strOutput << L"Error, extraction records and Bytes read do not match" << endl;

                for (short n = 0; n < dnsProto.m_DnsHeader.QDCOUNT; ++n)
                {
                    if (dnsProto.m_pQuestions.get()[n].LABEL == "_services._dns-sd._udp.local" && dnsProto.m_pQuestions.get()[n].QTYPE == 12)
                    {
                        vector<DnsProtokol::ANSWERITEM> AnList, NsList, ArList;
                        DnsProtokol::IDxSTRING PtrData1 = { 0, "_opcua-tcp._tcp.local" };
                        AnList.push_back({ { 0, dnsProto.m_pQuestions.get()[n].LABEL }, &PtrData1, 12, 1, 1400 });  // PTR Record auf Instance
                        DnsProtokol::IDxSTRING PtrData2 = { 0, "_http._tcp.local" };
                        AnList.push_back({ { 0, dnsProto.m_pQuestions.get()[n].LABEL }, &PtrData2, 12, 1, 1500 });  // PTR Record auf Instance
                        DnsProtokol::IDxSTRING PtrData3 = { 0, "_teamviewer._tcp.local" };
                        AnList.push_back({ { 0, dnsProto.m_pQuestions.get()[n].LABEL }, &PtrData3, 12, 1, 1600 });  // PTR Record auf Instance
                        SendAnswer(AnList, NsList, ArList, pUdpSocket);
                    }
                    else if (dnsProto.m_pQuestions.get()[n].LABEL == "_http._tcp.local" && dnsProto.m_pQuestions.get()[n].QTYPE == 12)
                    {
                        struct in_addr addrV4 = { 0 };
                        struct in6_addr addrV6 = { 0 };
                        string strHostname(512, 0);

                        if (gethostname(&strHostname[0], 512) == 0)
                            strHostname.erase(strHostname.find_last_not_of('\0') + 1);
                        strHostname += string(".local");

                        const auto& pItem = find_if(begin(m_maSockets), end(m_maSockets), [&pUdpSocket](const auto& it) { return it.first.get() == pUdpSocket; });
                        if (pItem != m_maSockets.end())
                        {
                            if (get<0>(pItem->second) == AF_INET)
                                inet_pton(AF_INET, get<1>(pItem->second).c_str(), &addrV4.s_addr);
                            else if (get<0>(pItem->second) == AF_INET6)
                                inet_pton(AF_INET6, get<1>(pItem->second).c_str(), &addrV6);
                        }

                        string strServiceName = "HTTP2SERV." + dnsProto.m_pQuestions.get()[n].LABEL;
                        vector<DnsProtokol::ANSWERITEM> AnList, NsList, ArList;

                        DnsProtokol::IDxSTRING PtrData = { 0, strServiceName };
                        AnList.push_back({ { 0, dnsProto.m_pQuestions.get()[n].LABEL }, &PtrData, 12, 1, 182 });    // PTR Record auf Instance

                        vector<string> vTxtData;// = { "Token1=Hallo World", "Token2=this are your", "Token3=Paramters to report" };
                        AnList.push_back({ { 0, strServiceName }, &vTxtData, 16, 1, 182 });             // TXT Record der Instance

                        DnsProtokol::SRVDATA SrvData = { 0, 0, 80,{ 0, strHostname } };
                        AnList.push_back({ { 0, strServiceName }, &SrvData, 33, 1, 182 });              // SRV Record der Instance

                        if (addrV4.s_addr != 0)
                            ArList.push_back({ { 0, strHostname }, &addrV4.s_addr, 1, 1, 182 });         // IP4 Record
                        if (*(reinterpret_cast<uint32_t*>(&addrV6)) != 0
                            || *(reinterpret_cast<uint32_t*>(&addrV6) + 1) != 0
                            || *(reinterpret_cast<uint32_t*>(&addrV6) + 2) != 0
                            || *(reinterpret_cast<uint32_t*>(&addrV6) + 3) != 0)
                            ArList.push_back({ { 0, strHostname }, &addrV6, 28, 1, 182 });              // IP6 Record

                        SendAnswer(AnList, NsList, ArList, pUdpSocket);
                    }
                }
            }
            else
                strOutput << dnsProto.m_strLastErrMsg.c_str();

            strOutput << endl;
            wcout << strOutput.str();
        }
    }

    void SendSrvSearch(string strSrvName, UdpSocket* pUdpSocket)   // _services._tcp.local
    {
        DnsProtokol dnsProto;
        size_t nBufLen = 0;
        if (dnsProto.BuildSearch(strSrvName, nullptr, nBufLen) != 0)
            return;

        string pBuffer(nBufLen, 0);
        size_t nSendSize = dnsProto.BuildSearch(strSrvName, &pBuffer[0], nBufLen);

        if (nBufLen != 0)
            wcout << L"Something went wrong in the buffer size calculation" << endl;

        const auto& pItem = find_if(begin(m_maSockets), end(m_maSockets), [&pUdpSocket](const auto& it) { return it.first.get() == pUdpSocket; });
        if (pItem != m_maSockets.end())
        {
            if (get<0>(pItem->second) == AF_INET)
                pUdpSocket->Write(&pBuffer[0], nSendSize, "224.0.0.251:5353");
            else if (get<0>(pItem->second) == AF_INET6)
                pUdpSocket->Write(&pBuffer[0], nSendSize, "[FF02::FB]:5353");
        }
    }

    void SendAnswer(vector<DnsProtokol::ANSWERITEM>& AnList, vector<DnsProtokol::ANSWERITEM>& NsList, vector<DnsProtokol::ANSWERITEM>& ArList, UdpSocket* pUdpSocket)
    {
        DnsProtokol dnsProto;
        size_t nBufLen = 0;
        if (dnsProto.BuildAnswer(AnList, NsList, ArList, nullptr, nBufLen) != 0)
            return;

        string pBuffer(nBufLen, 0);
        size_t nSendSize = dnsProto.BuildAnswer(AnList, NsList, ArList, &pBuffer[0], nBufLen);

        if (nBufLen != 0)
            wcout << L"Something went wrong in the buffer size calculation" << endl;

        // send it on his way
        const auto& pItem = find_if(begin(m_maSockets), end(m_maSockets), [&pUdpSocket](const auto& it) { return it.first.get() == pUdpSocket; });
        if (pItem != m_maSockets.end())
        {
            if (get<0>(pItem->second) == AF_INET)
                pUdpSocket->Write(&pBuffer[0], nSendSize, "224.0.0.251:5353");
            else if (get<0>(pItem->second) == AF_INET6)
                pUdpSocket->Write(&pBuffer[0], nSendSize, "[FF02::FB]:5353");
        }
    }

private:
    map<unique_ptr<UdpSocket>, tuple<int, string, uint32_t>> m_maSockets;
    map<RandIntervalTimer*, pair<UdpSocket*, string>> m_maTimer;
};


int main(int argc, const char* argv[])
{
#if defined(_WIN32) || defined(_WIN64)
    // Detect Memory Leaks
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));

    _setmode(_fileno(stdout), _O_U16TEXT);
#endif

    //locale::global(std::locale(""));

    mDnsServer mDnsSrv;
    mDnsSrv.Start();

#if defined(_WIN32) || defined(_WIN64)
    //while (::_kbhit() == 0)
    //    this_thread::sleep_for(chrono::milliseconds(1));
    _getch();
#else
    getchar();
#endif

    mDnsSrv.Stop();

    return 0;
}

