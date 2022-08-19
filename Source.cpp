/*
*	Module Name: KernelConnect
*	Author: Neehack, Inc
*	Copyright (C) 2022 Neehack Corporation
*   
*   This module is a simple anti-virus usermode that connects to neehackav engine/kernel/filesytem mini-filter driver.
*   All the open file events are received from kernel by this module and scanned.
*   If a file named "virus.txt" on open was detected. It alerts the kernel, so the kernel could prevent the open event. 
*/

#include <Windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <Wincrypt.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "FltLib.lib")

int MAX_BUFFER_LENGTH = 1024;
HANDLE port = NULL;

#define SCANNER_REPLY_MESSAGE_SIZE   (sizeof(FILTER_REPLY_HEADER) + sizeof(int))
typedef enum _AVSCAN_CONNECTION_TYPE {

    AvConnectForScan = 1,
    AvConnectForAbort,
    AvConnectForQuery

} AVSCAN_CONNECTION_TYPE, * PAVSCAN_CONNECTION_TYPE;

typedef struct _AV_CONNECTION_CONTEXT {

    AVSCAN_CONNECTION_TYPE   Type;

} AV_CONNECTION_CONTEXT, * PAV_CONNECTION_CONTEXT;



typedef struct _MY_MESSAGE {
    FILTER_MESSAGE_HEADER Header;
    WCHAR FullPathName[1024];
} MY_MESSAGE;

typedef struct _REPLY_MESSAGE_STRUCT {

    // Message header.
    FILTER_REPLY_HEADER header;

    // Flag to be set 
    // by user mode.
    WCHAR data[1024];
    int dataLength;

}REPLY_MESSAGE_STRUCT, * PREPLY_MESSAGE_STRUCT;

int main() {
    ULONG    bytesReturned = 0;
    AV_CONNECTION_CONTEXT connectionCtx = {};

    HRESULT hResult = 0;

    if (port == NULL) {
        /*
            FilterConnectCommunicationPort connects to avscan using "NeehackAVScanPort" port
        */
        connectionCtx.Type = AvConnectForScan;
        hResult = FilterConnectCommunicationPort(L"\\NeehackAVScanPort", 0, &connectionCtx, sizeof(AV_CONNECTION_CONTEXT), NULL, &port);
        printf("hresult: 0x%08x\n", hResult);
        if (hResult) {
            printf("Failed to Connect to Kernel\n");
            return -1;
        } 
    }
    printf("Connected to kernel\n");

    while (true) {
        MY_MESSAGE Message;
        memcpy(Message.FullPathName, "\x00", 1024);
        /*
           Always receive messages sent by kernel
           FilterGetMessage receives the message sent by kernal and store it in Message.FullPathName
        */
        hResult = FilterGetMessage(port, &Message.Header, sizeof(Message), NULL);
        if (FAILED(hResult)) {
            printf("Failed to get message, [0x%08x]\n", hResult);
            break;
        }

        REPLY_MESSAGE_STRUCT replyMessage;
        replyMessage.dataLength = (sizeof(FILTER_REPLY_HEADER) + 1024);

        ZeroMemory(&replyMessage, replyMessage.dataLength);

        replyMessage.header.Status = 0;
        replyMessage.header.MessageId = Message.Header.MessageId;
        /*
           If the filename sent by kernel contained virus.txt, tell the kernel that it is a malware, so the kernel could prevent the malware from opening.
        */
        if (wcsstr(Message.FullPathName, L"virus.txt")) {
            wcsncpy_s(replyMessage.data, L"malware detected", 16);
            printf("\nFullPathName: %ls, reply: %ls\n", Message.FullPathName, replyMessage.data);
        }
        else {
            wcsncpy_s(replyMessage.data, L"not infected", 12);
        }
        hResult = FilterReplyMessage(port,
            &replyMessage.header,
            replyMessage.dataLength);

        Message.FullPathName[replyMessage.dataLength] = '\0';
        
    }
    return 0;
}
