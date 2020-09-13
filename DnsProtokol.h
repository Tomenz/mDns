/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#pragma once

#include <string>
#include <vector>

using namespace std;

class DnsProtokol
{
    typedef struct
    {
        unsigned short ID;          // A 16 bit identifier assigned by the program that generates any kind of query
        unsigned short QR : 1;      // 0 = query, 1 = response
        unsigned short Opcode : 4;  // 0 = a standard query(QUERY), 1 = an inverse query(IQUERY), 2 = a server status request(STATUS), 3-15 = reserved for future use
        unsigned short AA : 1;      // Authoritative Answer
        unsigned short TC : 1;      // TrunCation
        unsigned short RD : 1;      // Recursion Desired
        unsigned short RA : 1;      // Recursion Available
        unsigned short Z : 3;       // Reserved for future use
        unsigned short RCODE : 4;   // Response code
        unsigned short QDCOUNT;     // number of entries in the question section
        unsigned short ANCOUNT;     // number of resource records in the answer section
        unsigned short NSCOUNT;     // number of name server resource records in the authority records section
        unsigned short ARCOUNT;     // number of resource records in the additional records section
    }DNSHEADER;

    typedef struct
    {
        string LABEL;
        unsigned short QTYPE;
        unsigned short QCLASS;
    }QUESTTION;

    typedef pair<size_t, string> LABELENTRY;
    typedef vector<LABELENTRY> LABELLIST;
    typedef pair<size_t, LABELLIST> OFFSETLABELLIST;
    typedef vector<OFFSETLABELLIST> OFFSETLIST;

    class DnsProtoException : exception
    {
    public:
        explicit DnsProtoException(const char* szMsg) : strError(szMsg) {}
        virtual ~DnsProtoException() throw() {}
        const char* what() const throw() { return strError.c_str(); }
    private:
        string strError;
    };

public:
    typedef pair<size_t, string> IDxSTRING;

    typedef struct
    {
        unsigned short Priority;
        unsigned short Weight;
        unsigned short Port;
        IDxSTRING strHost;
    }SRVDATA;

    typedef union
    {
        void* pVoid;
        IDxSTRING* ptrData;
        vector<string>* txtData;
        SRVDATA* svData;
        const char* szAddr;
    }RDATA;

    typedef struct
    {
        IDxSTRING strLabel;
        RDATA rData;
        unsigned short usType;
        unsigned short usClass;
        int iTtl;
    }ANSWERITEM;

    typedef struct
    {
        string LABEL;
        unsigned short TYPE;
        unsigned short CLASS;
        unsigned int TTL;
        unsigned short RDLENGTH;
        string RDATA;
    }RRECORDS;

public:
    DnsProtokol() {};
    DnsProtokol(unsigned char* szBuffer, size_t nBytInBuf);
    virtual ~DnsProtokol();

    size_t BuildSearch(const string& strQuestion, char* szBuffer, size_t& nBuflen);
    size_t BuildAnswer(vector<ANSWERITEM>& AnList, vector<ANSWERITEM>& NsList, vector<ANSWERITEM>& ArList, char* szBuffer, size_t& nBuflen);

private:
    size_t ExtractLabels(const unsigned char* pLabel, const unsigned char* pBuffer, size_t nBytInBuf, string& strLabel);
    size_t ExtractQuestion(const unsigned char* pCurPointer, const unsigned char* pBuffer, size_t nBytInBuf, short nNoQuestion, QUESTTION* pQuestion);
    size_t ExtractRRecords(const unsigned char* pCurPointer, const unsigned char* pBuffer, size_t nBytInBuf, short nNoRecords, RRECORDS* pRRecord);
    size_t BuildLabelReferenc(const string& strLabel, OFFSETLIST& OffListe);
    char* BuildLabels(OFFSETLIST& OffListe, size_t index, char* pBufPointer, size_t& nBufLen, size_t nBufOffset = 0);
    char* BuildQuestion(OFFSETLIST& lstOffsetListe, size_t iLabelIndex, short QTYPE, short QCLASS, char* pBufPointer, size_t& nBufLen, const char* pBufStart);
    char* BuildRRecord(OFFSETLIST& OffListe, size_t iLabelIndex, unsigned short TYPE, unsigned short CLASS, int TTL, char* pBufPointer, size_t& nBufLen, const char* pBufStart);
    char* BuildRData(unsigned short TYPE, RDATA rData, char* pBufPointer, size_t& nBufLen, OFFSETLIST& OffListe, const char* pBufStart);

public:
    DNSHEADER               m_DnsHeader;
    unique_ptr<QUESTTION[]> m_pQuestions;
    unique_ptr<RRECORDS[]>  m_pAnswers;
    unique_ptr<RRECORDS[]>  m_pNameServ;
    unique_ptr<RRECORDS[]>  m_pExtraRec;
    string                  m_strLastErrMsg;
    size_t                  m_nBytesDecodet;
};

