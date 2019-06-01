#include "https.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID ApplicationData(IN BYTE* stream, IN SIZE_T streamLength, IN BOOLEAN inbound)
{
    PTLSPlaintext plain = (PTLSPlaintext)stream;
    PHandshake phs = (PHandshake)((SIZE_T)plain + 5);//5是记录协议的大小.

    KdPrint(("application_data.\r\n"));


}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID Alert(IN BYTE* stream, IN SIZE_T streamLength, IN BOOLEAN inbound)
{
    PTLSPlaintext plain = (PTLSPlaintext)stream;
    PHandshake phs = (PHandshake)((SIZE_T)plain + 5);//5是记录协议的大小.

    KdPrint(("alert.\r\n"));


}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID ChangeCipherSpec(IN BYTE* stream, IN SIZE_T streamLength, IN BOOLEAN inbound)
{
    PTLSPlaintext plain = (PTLSPlaintext)stream;
    PHandshake phs = (PHandshake)((SIZE_T)plain + 5);//5是记录协议的大小.

    KdPrint(("change_cipher_spec.\r\n"));


}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID ClientHello(IN BYTE* stream, IN SIZE_T streamLength, IN BOOLEAN inbound)
{
    PTLSPlaintext plain = (PTLSPlaintext)stream;
    PHandshake phs = (PHandshake)((SIZE_T)plain + 5);//5是记录协议的大小.
    PCLIENTHELLO pch = (PCLIENTHELLO)((SIZE_T)phs + sizeof(Handshake));

    KdPrint(("client_hello.\r\n"));




}


VOID HandShake(IN BYTE* stream, IN SIZE_T streamLength, IN BOOLEAN inbound)
{
    PTLSPlaintext plain = (PTLSPlaintext)stream;
    PHandshake phs = (PHandshake)((SIZE_T)plain + 5);//5是记录协议的大小.

    KdPrint(("handshake.\r\n"));

    switch (phs->msg_type)
    {
    case hello_request:
        KdPrint(("hello_request.\r\n"));
        break;
    case client_hello:
        ClientHello(stream, streamLength, inbound);
        break;
    case server_hello:
        KdPrint(("server_hello.\r\n"));
        break;
    case certificate:
        KdPrint(("certificate.\r\n"));
        break;
    case server_key_exchange:
        KdPrint(("handshake.\r\n"));
        break;
    case certificate_request:
        KdPrint(("certificate_request.\r\n"));
        break;
    case server_hello_done:
        KdPrint(("server_hello_done.\r\n"));
        break;
    case certificate_verify:
        KdPrint(("certificate_verify.\r\n"));
        break;
    case client_key_exchange:
        KdPrint(("client_key_exchange.\r\n"));
        break;
    case finished:
        KdPrint(("finished.\r\n"));
        break;
    default:
        break;
    }

    KdPrint(("length:%d.\r\n", phs->length));
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID https(IN BYTE* stream, 
           IN SIZE_T streamLength,
           IN BOOLEAN inbound,
           IN USHORT localPort,
           IN USHORT remotePort)
{
    PTLSPlaintext plain = (PTLSPlaintext)stream;

    if (NULL == stream || 0 == streamLength)
    {
        return;
    }

    if (443 != localPort && 443 != remotePort) //大多是443 == remotePort
    {
        return;
    }

    if (streamLength < (sizeof(streamLength) - sizeof(BYTE)))
    {
        return;
    }

    //if (streamLength < (sizeof(streamLength) - sizeof(PBYTE) + plain->length))
    //{
    //    return;
    //}   

    if (3 == plain->version.major && 0 == plain->version.minor)
    {
        KdPrint(("SSL 3.0.\r\n"));
    }
    else if (3 == plain->version.major && 1 == plain->version.minor)
    {
        KdPrint(("TLS 1.0.\r\n"));
    }
    else if (3 == plain->version.major && 3 == plain->version.minor)
    {
        KdPrint(("TLS 1.2.\r\n"));
    }
    else if (3 == plain->version.major && 4 == plain->version.minor)
    {
        KdPrint(("TLS 1.3.\r\n"));
    }
    else
    {
        KdPrint(("Version:%d:%d.\r\n", plain->version.major, plain->version.minor));
    }    

    switch (plain->type)
    {
    case change_cipher_spec:
        ChangeCipherSpec(stream, streamLength, inbound);
        break;
    case alert:
        Alert(stream, streamLength, inbound);
        break;
    case handshake:        
        HandShake(stream, streamLength, inbound);
        break;
    case application_data:
        ApplicationData(stream, streamLength, inbound);
        break;
    default:
        KdPrint(("ContentType:%d.\r\n", plain->type));
        break;
    }

    KdPrint(("length:%d.\r\n", plain->length));

    if (!inbound) //出站
    {

    }
    else //入站
    {

    }

    KdPrint(("\r\n"));
    KdPrint(("\r\n"));
    KdPrint(("\r\n"));
}
