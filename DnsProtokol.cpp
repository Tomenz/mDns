/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#include <sstream>
#include <regex>
#include <iomanip>
#include <map>
#include <memory>

#if defined (_WIN32) || defined (_WIN64)
#include "WinSock2.h"
#else
#include <arpa/inet.h>
#endif
#include "DnsProtokol.h"


DnsProtokol::DnsProtokol(unsigned char* szBuffer, size_t nBytInBuf)
{
    copy(&szBuffer[0], &szBuffer[sizeof(DNSHEADER)], reinterpret_cast<unsigned char*>(&m_DnsHeader));
    m_DnsHeader.ID = ntohs(m_DnsHeader.ID);
    m_DnsHeader.QDCOUNT = ntohs(m_DnsHeader.QDCOUNT);
    m_DnsHeader.ANCOUNT = ntohs(m_DnsHeader.ANCOUNT);
    m_DnsHeader.NSCOUNT = ntohs(m_DnsHeader.NSCOUNT);
    m_DnsHeader.ARCOUNT = ntohs(m_DnsHeader.ARCOUNT);

    const unsigned char* pBufPointer = szBuffer + sizeof(DNSHEADER);

    try
    {
        if (m_DnsHeader.QDCOUNT + m_DnsHeader.ANCOUNT + m_DnsHeader.NSCOUNT + m_DnsHeader.ARCOUNT > 150)
            throw DnsProtoException("Invalid buffer content");

        if (m_DnsHeader.QDCOUNT > 0)
        {
            m_pQuestions = make_unique<QUESTTION[]>(m_DnsHeader.QDCOUNT);
            pBufPointer += ExtractQuestion(pBufPointer, szBuffer, nBytInBuf, m_DnsHeader.QDCOUNT, m_pQuestions.get());
        }

        if (m_DnsHeader.ANCOUNT > 0)
        {
            m_pAnswers = make_unique<RRECORDS[]>(m_DnsHeader.ANCOUNT);
            pBufPointer += ExtractRRecords(pBufPointer, szBuffer, nBytInBuf, m_DnsHeader.ANCOUNT, m_pAnswers.get());
        }

        if (m_DnsHeader.NSCOUNT > 0)
        {
            m_pNameServ = make_unique<RRECORDS[]>(m_DnsHeader.NSCOUNT);
            pBufPointer += ExtractRRecords(pBufPointer, szBuffer, nBytInBuf, m_DnsHeader.NSCOUNT, m_pNameServ.get());
        }

        if (m_DnsHeader.ARCOUNT > 0)
        {
            m_pExtraRec = make_unique<RRECORDS[]>(m_DnsHeader.ARCOUNT);
            pBufPointer += ExtractRRecords(pBufPointer, szBuffer, nBytInBuf, m_DnsHeader.ARCOUNT, m_pExtraRec.get());
        }

        m_nBytesDecodet = pBufPointer - szBuffer;
    }

    catch (exception& ex)
    {
        m_strLastErrMsg = ex.what();
    }
}


DnsProtokol::~DnsProtokol()
{
}

size_t DnsProtokol::BuildSearch(const string& strQuestion, char* szBuffer, size_t& nBuflen)
{
    OFFSETLIST lstOffsetListe;
    size_t iLabRef = BuildLabelReferenc(strQuestion, lstOffsetListe);

    size_t nBufLenNeeded = 0;
    BuildQuestion(lstOffsetListe, iLabRef, 12, 1, 0, nBufLenNeeded, nullptr);
    nBufLenNeeded += sizeof(DNSHEADER);

    if (szBuffer == nullptr || nBuflen < nBufLenNeeded)
    {
        nBuflen = nBufLenNeeded;
        return 0;
    }

    DNSHEADER* pDnsHeader = reinterpret_cast<DNSHEADER*>(szBuffer);
    pDnsHeader->ID = htons(0);
    pDnsHeader->QDCOUNT = htons(1);

    char* pBufPointer = szBuffer + sizeof(DNSHEADER);
    nBuflen -= sizeof(DNSHEADER);
    pBufPointer = BuildQuestion(lstOffsetListe, iLabRef, 12, 1, pBufPointer, nBuflen, szBuffer);
    return pBufPointer - szBuffer;
}

size_t DnsProtokol::BuildAnswer(vector<ANSWERITEM>& AnList, vector<ANSWERITEM>& NsList, vector<ANSWERITEM>& ArList, char* szBuffer, size_t& nBuflen)
{
    // Build the Label reference table
    OFFSETLIST lstOffsetListe;
    auto fnExtractLabels = [&lstOffsetListe, this](vector<ANSWERITEM>& theList)
    {
        for (auto& item : theList)
        {
            item.strLabel.first = BuildLabelReferenc(item.strLabel.second, lstOffsetListe);
            if (item.usType == 12)  // PTR
                item.rData.ptrData->first = BuildLabelReferenc(item.rData.ptrData->second, lstOffsetListe);
            if (item.usType == 33)  // PTR
                item.rData.svData->strHost.first = BuildLabelReferenc(item.rData.svData->strHost.second, lstOffsetListe);
        }
    };
    fnExtractLabels(AnList);
    fnExtractLabels(NsList);
    fnExtractLabels(ArList);

    // Calculate the needed buffer space
    auto fnCalcBufferSize = [&lstOffsetListe, this](vector<ANSWERITEM>& theList, size_t& nTotalSize)
    {
        for (const auto& item : theList)
        {
            size_t nRRLen = 0;
            BuildRRecord(lstOffsetListe, item.strLabel.first, item.usType, item.usClass, item.iTtl, nullptr, nRRLen, nullptr);
            nTotalSize += nRRLen;
            size_t nLenRData = 0;
            BuildRData(item.usType, item.rData, nullptr, nLenRData, lstOffsetListe, nullptr);
            nTotalSize += nLenRData;
        }
    };
    size_t nBufLenNeeded = 0;
    fnCalcBufferSize(AnList, nBufLenNeeded);
    fnCalcBufferSize(NsList, nBufLenNeeded);
    fnCalcBufferSize(ArList, nBufLenNeeded);
    nBufLenNeeded += sizeof(DNSHEADER);

    if (szBuffer == nullptr || nBuflen < nBufLenNeeded)
    {
        nBuflen = nBufLenNeeded;
        return 0;
    }

    fill(szBuffer, szBuffer + sizeof(DNSHEADER), 0);
    char* pPtrBuffer = szBuffer + sizeof(DNSHEADER);
    nBuflen -= sizeof(DNSHEADER);

    // Build the package together
    auto fnBuildRecords = [&lstOffsetListe, this](vector<ANSWERITEM>& theList, char* pPtrBuffer, size_t& nTotalSize, const char* pBufStart) -> char*
    {
        for (const auto& item : theList)
        {
            pPtrBuffer = BuildRRecord(lstOffsetListe, item.strLabel.first, item.usType, item.usClass, item.iTtl, pPtrBuffer, nTotalSize, pBufStart);
            pPtrBuffer = BuildRData(item.usType, item.rData, pPtrBuffer, nTotalSize, lstOffsetListe, pBufStart);
        }
        return pPtrBuffer;
    };
    pPtrBuffer = fnBuildRecords(AnList, pPtrBuffer, nBuflen, szBuffer);
    pPtrBuffer = fnBuildRecords(NsList, pPtrBuffer, nBuflen, szBuffer);
    pPtrBuffer = fnBuildRecords(ArList, pPtrBuffer, nBuflen, szBuffer);

    // Set the DNS header data
    DNSHEADER* pDnsHeader = reinterpret_cast<DNSHEADER*>(szBuffer);
    pDnsHeader->ID = 0;
    pDnsHeader->Opcode = 0;
    pDnsHeader->QR = 1;
    pDnsHeader->RD = 0;
    pDnsHeader->AA = 0;
    pDnsHeader->ANCOUNT = htons(static_cast<unsigned short>(AnList.size()));
    pDnsHeader->NSCOUNT = htons(static_cast<unsigned short>(NsList.size()));
    pDnsHeader->ARCOUNT = htons(static_cast<unsigned short>(ArList.size()));

    return pPtrBuffer - szBuffer;
}

size_t DnsProtokol::ExtractLabels(const unsigned char* pLabel, const unsigned char* pBuffer, size_t nBytInBuf, string& strLabel)
{
    const unsigned char* pStart = pLabel;
    char iTokenLen = *pLabel++;
    while (iTokenLen != 0)
    {
        if ((iTokenLen & 0xc0) == 0xc0)
        {
            size_t nOffset = ntohs(*((short*)--pLabel)) & 0x3fff;
            if (nOffset > static_cast<size_t>(pLabel - pBuffer))
                throw DnsProtoException("Error extraction label");
            ExtractLabels(pBuffer + nOffset, pBuffer, nBytInBuf, strLabel);
            pLabel += 2;
            break;
        }
        else
        {
            if (iTokenLen > 64)
                throw DnsProtoException("Error extraction label");
            if (pLabel + iTokenLen > pBuffer + nBytInBuf)
                throw DnsProtoException("Invalid buffer content");  // In case we recieved a corupted datagram
            if (strLabel.empty() == false)
                strLabel += ".";
            strLabel += string(reinterpret_cast<const char*>(pLabel), iTokenLen);
            pLabel += iTokenLen;
        }
        iTokenLen = *pLabel++;
    }

    return pLabel - pStart;
}

size_t DnsProtokol::ExtractQuestion(const unsigned char* pCurPointer, const unsigned char* pBuffer, size_t nBytInBuf, short nNoQuestion, QUESTTION* pQuestion)
{
    const unsigned char* pStart = pCurPointer;
    for (short n = 0; n < nNoQuestion; ++n)
    {
        pCurPointer += ExtractLabels(pCurPointer, pBuffer, nBytInBuf, pQuestion[n].LABEL);
        pQuestion[n].QTYPE = ntohs(*(short*)pCurPointer);
        pQuestion[n].QCLASS = ntohs(*(short*)(pCurPointer + 2));
        pCurPointer += 4;

        if (pCurPointer > pBuffer + nBytInBuf)
            throw DnsProtoException("Invalid buffer content");  // In case we recieved a corupted datagram
    }

    return pCurPointer - pStart;
}

size_t DnsProtokol::ExtractRRecords(const unsigned char* pCurPointer, const unsigned char* pBuffer, size_t nBytInBuf, short nNoRecords, RRECORDS* pRRecord)
{
    const unsigned char* pStart = pCurPointer;
    for (short n = 0; n < nNoRecords; ++n)
    {
        pCurPointer += ExtractLabels(pCurPointer, pBuffer, nBytInBuf, pRRecord[n].LABEL);
        if (pCurPointer + 10 > pBuffer + nBytInBuf)
            throw DnsProtoException("Invalid buffer content");  // In case we recieved a corupted datagram
        pRRecord[n].TYPE = ntohs(*reinterpret_cast<const unsigned short*>(pCurPointer));
        pRRecord[n].CLASS = ntohs(*reinterpret_cast<const unsigned short*>(pCurPointer + 2));
        pRRecord[n].TTL = ntohl(*reinterpret_cast<const unsigned int*>(pCurPointer + 4));
        pRRecord[n].RDLENGTH = ntohs(*reinterpret_cast<const unsigned short*>(pCurPointer + 8));
        pCurPointer += 10;

        if (pCurPointer + pRRecord[n].RDLENGTH > pBuffer + nBytInBuf)
            throw DnsProtoException("Invalid buffer content");  // In case we recieved a corupted datagram

        switch (pRRecord[n].TYPE)
        {
        case 1:     // A    (IPv4)
        {
            stringstream ss;
            ss << static_cast<unsigned int>(*pCurPointer) << "." << static_cast<unsigned int>(*(pCurPointer + 1)) << "." << static_cast<unsigned int>(*(pCurPointer + 2)) << "." << static_cast<unsigned int>(*(pCurPointer + 3));
            pRRecord[n].RDATA = ss.str();
        }
        break;
        case 12:    // PTR
            ExtractLabels(pCurPointer, pBuffer, nBytInBuf, pRRecord[n].RDATA);
            break;
        case 16:    // TXT
        {
            size_t nTxtOff = 0;
            while (nTxtOff < pRRecord[n].RDLENGTH)
            {
                size_t nTxtLen = *(pCurPointer + nTxtOff);
                if (nTxtLen > 0)
                {
                    if (nTxtOff != 0)
                        pRRecord[n].RDATA += ",";
                    pRRecord[n].RDATA += "\"" + string(reinterpret_cast<const char*>(pCurPointer + nTxtOff + 1), nTxtLen) + "\"";
                }
                nTxtOff += nTxtLen + 1;
            }
        }
        break;
        case 28:    // AAAA (IPv6)
        {
            stringstream ss;
            for (int i = 0; i < pRRecord[n].RDLENGTH; ++i)
            {
                if (i > 0 && i % 2 == 0) ss << ":";
                ss << setfill('0') << hex << setw(2) << static_cast<unsigned int>(*(pCurPointer + i));
            }
            pRRecord[n].RDATA = ss.str();
        }
        break;
        case 33:    // SRV
        {
            stringstream ss;
            ss << ntohs(*(unsigned short*)pCurPointer) << " " << ntohs(*(unsigned short*)(pCurPointer + 2)) << " " << ntohs(*(unsigned short*)(pCurPointer + 4)) << " ";
            string strTemp;
            if (pRRecord[n].RDLENGTH > 6)
                ExtractLabels(pCurPointer + 6, pBuffer, nBytInBuf, strTemp);
            ss << strTemp;
            pRRecord[n].RDATA = ss.str();
        }
        break;
        case 41:    // EDNS (Extending DNS)
        {
            short sOptionCode = ntohs(*(unsigned short*)pCurPointer);
            short sOptionLen = ntohs(*(unsigned short*)pCurPointer + 2);
            stringstream ss;
            ss << "OptCode: " << sOptionCode << ", OptLen: " << sOptionLen << " -> ";
            for (int i = 0; i < pRRecord[n].RDLENGTH - 4; ++i)
            {
                if (i > 0) ss << " ";
                ss << "0x" << setfill('0') << hex << setw(2) << static_cast<unsigned int>(*(pCurPointer + 4 + i));
            }
            pRRecord[n].RDATA = ss.str();
        }
        break;
        case 47:    // NSEC
        {
            size_t iLabelSize = ExtractLabels(pCurPointer, pBuffer, nBytInBuf, pRRecord[n].RDATA);
            if (pRRecord[n].RDLENGTH > iLabelSize)
            {
                stringstream ss;
                for (size_t i = 0; i < pRRecord[n].RDLENGTH - iLabelSize; ++i)
                {
                    if (i > 0) ss << "|";
                    ss << setfill('0') << hex << setw(2) << static_cast<unsigned int>(*(pCurPointer + iLabelSize + i));
                }
                pRRecord[n].RDATA += ", " + ss.str();
            }
        }
        break;
        default:
            break;
        }

        pCurPointer += pRRecord[n].RDLENGTH;
    }

    return pCurPointer - pStart;
}

size_t DnsProtokol::BuildLabelReferenc(const string& strLabel, OFFSETLIST& OffListe)
{
    LABELLIST vLabelTokens;
    regex seperator("\\.");
    sregex_token_iterator token(begin(strLabel), end(strLabel), seperator, -1);
    while (token != sregex_token_iterator())
        vLabelTokens.emplace_back(0, *token++);

    map<size_t, size_t> mFound;
    for (size_t n = 0; n < OffListe.size(); ++n)
    {
        for (size_t i = 0; i < vLabelTokens.size(); ++i)
        {
            for (size_t m = 0; m < OffListe[n].second.size(); ++m)
            {
                if (equal(begin(OffListe[n].second) + m, end(OffListe[n].second), begin(vLabelTokens) + i, end(vLabelTokens), [](const LABELENTRY& item1, const LABELENTRY& item2) -> bool { return item1.second == item2.second ? true : false; }) == true) // Gleicher Label bereits enthalten
                {
                    // m == 0 und i == 0, das gleiche Label gibt es schon bei n
                    // i = 0, das neue Label komplett in einem bereits bestehendem Label n[m] enthalten
                    // i > 0, der Teil ab i ist in einem bereits bestehenden Label n[m] enthalten

                    // wie write in the string how already exist somewhere else the Item ( + 1) and Index where it starts
                    // the + 1 to different in the first label with zero index
                    mFound.emplace(vLabelTokens.size() - i, ((n + 1) << 16) | m);
                }
            }
        }
    }

    OffListe.emplace_back(0, vLabelTokens);
    if (mFound.size() > 0)
        OffListe.back().second[vLabelTokens.size() - mFound.rbegin()->first].first = mFound.rbegin()->second;
    return OffListe.size();
}

char* DnsProtokol::BuildLabels(OFFSETLIST& OffListe, size_t index, char* pBufPointer, size_t& nBufLen, size_t nBufOffset/* = 0*/)
{
    if (index == 0)
        return pBufPointer;

    size_t nLen = 0, nLenOffset = 1;  // plus the ending 0 byte
    for (const auto& strToken : OffListe[index - 1].second)
    {
        if (strToken.first != 0)
        {   // Der Rest des Labels ist optimiert und gibt es bereits. Wir brauchen noch 2 Bytes um den Pointer zu platzieren
            nLen += 2;
            nLenOffset = 0;
            break;
        }
        nLen += strToken.second.size() + 1;
    }

    if (nLen + nLenOffset > nBufLen)
    {
        nBufLen = nLen + nLenOffset;
        return pBufPointer;
    }
    nBufLen -= nLen + nLenOffset;

    OffListe[index - 1].first = nBufOffset;
    for (const auto& strToken : OffListe[index - 1].second)
    {
        if (strToken.first != 0)
        {   // Der Rest des Labels ist optimiert und gibt es bereits. Wir brauchen noch 2 Bytes um den Pointer zu platzieren
            index = ((strToken.first >> 16) & 0xffff) - 1;
            nBufOffset = OffListe[index].first;
            for (size_t n = 0; n < (strToken.first & 0xffff); ++n)
                nBufOffset += OffListe[index].second[n].second.size() + 1;
            *(reinterpret_cast<unsigned short*>(pBufPointer)) = htons(0xc000 | static_cast<uint16_t>(nBufOffset));
            return pBufPointer + 2;
        }

        *pBufPointer++ = static_cast<char>(strToken.second.size());
        copy(begin(strToken.second), end(strToken.second), pBufPointer);
        pBufPointer += strToken.second.size();
    }
    *pBufPointer++ = 0;   // abschließendes 0 Zeichen hinter dem Label
    return pBufPointer;
}

char* DnsProtokol::BuildQuestion(OFFSETLIST& lstOffsetListe, size_t iLabelIndex, short QTYPE, short QCLASS, char* pBufPointer, size_t& nBufLen, const char* pBufStart)
{
    size_t nSaveLen = nBufLen;
    pBufPointer = BuildLabels(lstOffsetListe, iLabelIndex, pBufPointer, nBufLen, pBufPointer - pBufStart);
    if (nBufLen >= nSaveLen) // the buffer is to small, nothing done, only get the site
    {
        nBufLen += 4;
        return pBufPointer;
    }
    else if (nBufLen < 4)
    {
        nBufLen = (nSaveLen - nBufLen) + 4;
        return pBufPointer;
    }
    nBufLen -= 4;

    *(reinterpret_cast<short*>(pBufPointer)) = htons(QTYPE);
    *(reinterpret_cast<short*>(pBufPointer + 2)) = htons(QCLASS);
    pBufPointer += 4;
    return pBufPointer;
}

char* DnsProtokol::BuildRRecord(OFFSETLIST& OffListe, size_t iLabelIndex, unsigned short TYPE, unsigned short CLASS, int TTL, char* pBufPointer, size_t& nBufLen, const char* pBufStart)
{
    size_t nSaveLen = nBufLen;
    pBufPointer = BuildLabels(OffListe, iLabelIndex, pBufPointer, nBufLen, pBufPointer - pBufStart);
    if (nBufLen >= nSaveLen) // the buffer is to small, nothing done, only get the size
    {
        nBufLen += 10;
        return pBufPointer;
    }
    else if (nBufLen < 10)  // Rest of the buffer is to small
    {
        nBufLen = (nSaveLen - nBufLen) + 10;
        return pBufPointer;
    }
    nBufLen -= 10;

    *(reinterpret_cast<short*>(pBufPointer)) = htons(TYPE);
    *(reinterpret_cast<short*>(pBufPointer + 2)) = htons(CLASS);
    *(reinterpret_cast<int*>(pBufPointer + 4)) = htonl(TTL);
    *(reinterpret_cast<short*>(pBufPointer + 8)) = 0;
    pBufPointer += 10;

    return pBufPointer;
}

char* DnsProtokol::BuildRData(unsigned short TYPE, RDATA rData, char* pBufPointer, size_t& nBufLen, OFFSETLIST& OffListe, const char* pBufStart)
{
    short* pRdataLen = reinterpret_cast<short*>(pBufPointer - 2);
    size_t nSaveLen = nBufLen;

    switch (TYPE)
    {
    case 1:     // A    (IPv4) -> pData points to struct in_addr.s_addr
        if (nBufLen < 4)
        {
            nBufLen = 4;
            break;
        }
        for (int i = 0; i < 4; ++i)
            *pBufPointer++ = *(reinterpret_cast<char*>(rData.pVoid) + i);
        nBufLen -= 4;
        *pRdataLen = htons(4);
        break;
    case 12:    // PTR
        pBufPointer = BuildLabels(OffListe, rData.ptrData->first, pBufPointer, nBufLen, pBufPointer - pBufStart);
        if (pBufPointer != nullptr)
            *pRdataLen = htons(static_cast<uint16_t>(nSaveLen - nBufLen));
        break;
    case 16:    // TXT -> pData points to vector<string>
    {
        vector<string>* pStrings = rData.txtData;
        size_t nLen = 0;
        for (size_t n = 0; n < pStrings->size(); ++n)
            nLen += pStrings->at(n).size() + 1;
        if (nBufLen < nLen)
        {
            nBufLen = nLen;
            break;
        }
        nBufLen -= nLen;
        for (size_t n = 0; n < pStrings->size(); ++n)
        {
            *pBufPointer++ = static_cast<char>(pStrings->at(n).size());
            copy(begin(pStrings->at(n)), begin(pStrings->at(n)) + pStrings->at(n).size(), pBufPointer);
            pBufPointer += pStrings->at(n).size();
        }
        if (pBufPointer != nullptr)
            *pRdataLen = htons(static_cast<uint16_t>(nSaveLen - nBufLen));
    }
    break;
    case 28:    // AAAA (IPv6) -> pData points to struct in6_addr.s6_addr
        if (nBufLen < 16)
        {
            nBufLen = 16;
            break;
        }
        for (int i = 0; i < 16; ++i)
            *pBufPointer++ = *(reinterpret_cast<char*>(rData.pVoid) + i);
        nBufLen -= 16;
        *pRdataLen = htons(16);
        break;
    case 33:    // SRV
        if (nBufLen > 6)
        {
            *reinterpret_cast<unsigned short*>(pBufPointer) = htons(rData.svData->Priority);
            *(reinterpret_cast<unsigned short*>(pBufPointer) + 1) = htons(rData.svData->Weight);
            *(reinterpret_cast<unsigned short*>(pBufPointer) + 2) = htons(rData.svData->Port);
            nBufLen -= 6;
            pBufPointer += 6;
            pBufPointer = BuildLabels(OffListe, rData.svData->strHost.first, pBufPointer, nBufLen, pBufPointer - pBufStart);
            if (nBufLen > nSaveLen - 6) // the buffer is to small, nothing done, only get the site
                nBufLen += 6;
            else
                *pRdataLen = htons(static_cast<uint16_t>(nSaveLen - nBufLen));
        }
        else
        {
            nBufLen = 0;
            pBufPointer = BuildLabels(OffListe, rData.svData->strHost.first, pBufPointer + 6, nBufLen, pBufPointer - pBufStart + 6);
            nBufLen += 6;
        }
        break;
    default:
        break;
    }
    return pBufPointer;
}
