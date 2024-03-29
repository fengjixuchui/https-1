#pragma once

#include <ndis.h>
#include <ntddk.h>
#include <fwpmk.h>
#include <windef.h>


//////////////////////////////////////////////////////////////////////////////////////////////////
//记录协议的结构的定义.


/*
怪哉!在应用层的.cpp里可以编译.
在这里不可以编译(包括.h和.c文件).
在应用层的.h文件里也不可以编译.
*/
typedef enum _ContentType/* : BYTE */{
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,

    MAX_CONTENT_TYPE = 255
}ContentType;

typedef struct _ProtocolVersion {
    BYTE major;
    BYTE minor;
}ProtocolVersion;

#pragma pack(1)
typedef struct _TLSPlaintext {
    BYTE type;//可以定义为一个字节大小的枚举类型ContentType
    ProtocolVersion version;
    UINT16 length;//原来的定义是INT16,可是看到了负数.
    PBYTE data;//opaque fragment[TLSPlaintext.length];
} TLSPlaintext, *PTLSPlaintext;


//////////////////////////////////////////////////////////////////////////////////////////////////
//Handshake Protocol


typedef enum _HandshakeType /* : BYTE */ {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,

    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,

    finished = 20,

    Max_HandshakeType = 255
} HandshakeType;

/*
定义一个32位的整数的位联合.
*/
typedef struct _Handshake {
    unsigned msg_type : 8;// BYTE msg_type;    /* handshake type */
    unsigned length : 24;// UINT24 length;    /* bytes in message */
} Handshake, *PHandshake;

//struct {
//    HandshakeType msg_type;    /* handshake type */
//    uint24 length;             /* bytes in message */
//    select(HandshakeType) {
//              case hello_request:       HelloRequest;
//              case client_hello:        ClientHello;
//              case server_hello:        ServerHello;
//              case certificate:         Certificate;
//              case server_key_exchange: ServerKeyExchange;
//              case certificate_request: CertificateRequest;
//              case server_hello_done:   ServerHelloDone;
//              case certificate_verify:  CertificateVerify;
//              case client_key_exchange: ClientKeyExchange;
//              case finished:            Finished;
//    } body;
//} Handshake;


//////////////////////////////////////////////////////////////////////////////////////////////////
//Hello Extensions


//enum {
//    signature_algorithms(13), (65535)
//} ExtensionType;
//struct {
//    ExtensionType extension_type;
//    opaque extension_data<0..2 ^ 16 - 1>;
//} Extension;


//////////////////////////////////////////////////////////////////////////////////////////////////
//Client Hello

#pragma pack(1)
typedef struct _Random {
    UINT32 gmt_unix_time;//uint32
    BYTE random_bytes[28];//opaque
} Random;

// opaque SessionID<0..32>;

//uint8 CipherSuite[2]; 

//enum { null(0), (255) } CompressionMethod;

#pragma pack(1)
typedef struct _CLIENTHELLO {
    ProtocolVersion client_version;
    Random random;
    BYTE session_id;// SessionID session_id;
    //这里好像还有个两字节的长度成员.好像是cipher_suites的大小.
    BYTE cipher_suites[2];// CipherSuite cipher_suites<2..2 ^ 16 - 2>;
    BYTE CompressionMethod;// CompressionMethod compression_methods<1..2 ^ 8 - 1>;
    //select(extensions_present) {
    //          case false:
    //              struct {};
    //          case true:
    //              Extension extensions<0..2 ^ 16 - 1>;
    //};
} CLIENTHELLO, *PCLIENTHELLO;


//////////////////////////////////////////////////////////////////////////////////////////////////
//Change Cipher Spec Protocol


typedef enum _CHANGECIPHERSPEC/* : BYTE */ {
    CHANGE_CIPHER_SPEC = 1,//change_cipher_spec

    MAX_CHANGE_CIPHERSPEC = 255
}CHANGECIPHERSPEC;


//////////////////////////////////////////////////////////////////////////////////////////////////
//Alert Protocol


typedef enum _AlertLevel/* : BYTE */ {
    warning = 1,
    fatal = 2,

    MAX_ALERT_LEVEL = 255
} AlertLevel;


typedef enum _AlertDescription/* : BYTE */ {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed_RESERVED = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate_RESERVED = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction_RESERVED = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    user_canceled = 90,
    no_renegotiation = 100,
    unsupported_extension = 110,

    MAX_ALERTDESCRIPTION = 255
} AlertDescription;


typedef struct _ALERT {
    BYTE level;//AlertLevel
    BYTE description;//AlertDescription
} ALERT;


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID https(IN BYTE* stream,
           IN SIZE_T streamLength,
           IN BOOLEAN inbound,
           IN USHORT localPort,
           IN USHORT remotePort);
