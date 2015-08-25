//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import(
	"bytes"
	"encoding/binary"
)

type NegotiateMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}


 /*
	Negotiate Message Structure From: http://www.innovation.ch/personal/ronald/ntlm.html
	
	struct {
        byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        byte    type;            // 0x01
        byte    zero[3];
        short   flags;           // 0xb203
        byte    zero[2];

        short   dom_len;         // domain string length
        short   dom_len;         // domain string length
        short   dom_off;         // domain string offset
        byte    zero[2];

        short   host_len;        // host string length
        short   host_len;        // host string length
        short   host_off;        // host string offset (always 0x20)
        byte    zero[2];

        byte    host[*];         // host string (ASCII)
        byte    dom[*];          // domain string (ASCII)
    } type-1-message
                 0       1       2       3
             +-------+-------+-------+-------+
         0:  |  'N'  |  'T'  |  'L'  |  'M'  |
             +-------+-------+-------+-------+
         4:  |  'S'  |  'S'  |  'P'  |   0   |
             +-------+-------+-------+-------+
         8:  |   1   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        12:  | 0x03  | 0xb2  |   0   |   0   |
             +-------+-------+-------+-------+
        16:  | domain length | domain length |
             +-------+-------+-------+-------+
        20:  | domain offset |   0   |   0   |
             +-------+-------+-------+-------+
        24:  |  host length  |  host length  |
             +-------+-------+-------+-------+
        28:  |  host offset  |   0   |   0   |
             +-------+-------+-------+-------+
        32:  |  host string                  |
             +                               +
             .                               .
             .                               .
             +             +-----------------+
             |             | domain string   |
             +-------------+                 +
             .                               .
             .                               .
             +-------+-------+-------+-------+
*/

func (n *NegotiateMessage) Bytes() []byte {
	
	payloadLen := n.DomainNameFields.Len + n.WorkstationFields.Len
	messageLen := 32 + n.DomainNameFields.Len + n.WorkstationFields.Len

	messageBytes := make([]byte, 0, messageLen + payloadLen)
	buffer := bytes.NewBuffer(messageBytes)

	buffer.Write(n.Signature)
	binary.Write(buffer, binary.LittleEndian, n.MessageType)
	binary.Write(buffer, binary.LittleEndian, n.NegotiateFlags)

	buffer.Write(n.DomainNameFields.Bytes())
	buffer.Write(n.WorkstationFields.Bytes())

	// Write out the payloads
	buffer.Write(n.DomainNameFields.Payload)
	buffer.Write(n.WorkstationFields.Payload)

	return buffer.Bytes()
}