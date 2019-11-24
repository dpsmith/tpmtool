package tpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

func parseTcgBiosSpecIDEvent (handle io.Reader) (*TcgBiosSpecIDEvent, error) {
	var endianess binary.ByteOrder = binary.LittleEndian
	var biosSpecEvent TcgBiosSpecIDEvent

	if err := binary.Read(handle, endianess, &biosSpecEvent.signature); err != nil {
		return nil, err
	}

	identifier := string(bytes.Trim(biosSpecEvent.signature[:], "\x00"))
	if string(identifier) != TCGOldEfiFormatID {
		return nil, nil
	}

	if err := binary.Read(handle, endianess, &biosSpecEvent.platformClass); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &biosSpecEvent.specVersionMinor); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &biosSpecEvent.specVersionMajor); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &biosSpecEvent.specErrata); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &biosSpecEvent.uintnSize); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &biosSpecEvent.vendorInfoSize); err != nil {
		return nil, err
	}

	biosSpecEvent.vendorInfo = make([]byte, biosSpecEvent.vendorInfoSize)
	if err := binary.Read(handle, endianess, &biosSpecEvent.vendorInfo); err != nil {
		return nil, err
	}

	return &biosSpecEvent, nil
}

func parseEfiSpecEvent (handle io.Reader) (*TcgEfiSpecIDEvent, error) {
	var endianess binary.ByteOrder = binary.LittleEndian
	var efiSpecEvent TcgEfiSpecIDEvent

	if err := binary.Read(handle, endianess, &efiSpecEvent.signature); err != nil {
		return nil, err
	}

	identifier := string(bytes.Trim(efiSpecEvent.signature[:], "\x00"))
	if string(identifier) != TCGAgileEventFormatID {
		return nil, nil
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.platformClass); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.specVersionMinor); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.specVersionMajor); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.specErrata); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.uintnSize); err != nil {
		return nil, err
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.numberOfAlgorithms); err != nil {
		return nil, err
	}

	efiSpecEvent.digestSizes = make([]TcgEfiSpecIDEventAlgorithmSize, efiSpecEvent.numberOfAlgorithms)
	for i := uint32(0); i < efiSpecEvent.numberOfAlgorithms; i++ {
		if err := binary.Read(handle, endianess, &efiSpecEvent.digestSizes[i].algorithID); err != nil {
			return nil, err
		}
		if err := binary.Read(handle, endianess, &efiSpecEvent.digestSizes[i].digestSize); err != nil {
			return nil, err
		}
	}

	if err := binary.Read(handle, endianess, &efiSpecEvent.vendorInfoSize); err != nil {
		return nil, err
	}

	efiSpecEvent.vendorInfo = make([]byte, efiSpecEvent.vendorInfoSize)
	if err := binary.Read(handle, endianess, &efiSpecEvent.vendorInfo); err != nil {
		return nil, err
	}

	return &efiSpecEvent, nil
}

// type TcgPcrEvent struct {
// 	pcrIndex  uint32
// 	eventType uint32
// 	digest    [20]byte
// 	eventSize uint32
// 	event     []byte
// }

func parseTcgPcrEvent(handle io.Reader) (*TcgPcrEvent, error) {
	var endianess binary.ByteOrder = binary.LittleEndian
	var pcrEvent TcgPcrEvent

	if err := binary.Read(handle, endianess, &pcrEvent.pcrIndex); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, endianess, &pcrEvent.eventType); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, endianess, &pcrEvent.digest); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, endianess, &pcrEvent.eventSize); err != nil {
		return nil, err
	}

	pcrEvent.event = make([]byte, pcrEvent.eventSize)
	if err := binary.Read(handle, endianess, &pcrEvent.event); err != nil {
		return nil, err
	}

	return &pcrEvent, nil
}

func (e *TcgPcrEvent) PcrIndex() int {
	return int(e.pcrIndex)
}

func (e *TcgPcrEvent) PcrEventName() string {
	if BIOSLogTypes[BIOSLogID(e.eventType)] != "" {
		return BIOSLogTypes[BIOSLogID(e.eventType)]
	}
	if EFILogTypes[EFILogID(e.eventType)] != "" {
		return EFILogTypes[EFILogID(e.eventType)]
	}

	return ""
}

func (e *TcgPcrEvent) PcrEventData() string {
	if BIOSLogID(e.eventType) == EvNoAction {
		return string(e.event)
	} else {
		eventDataString, _ := getEventDataString(e.eventType, e.event)
		if eventDataString != nil {
			return *eventDataString
		}
	}

	return ""
}

func (e *TcgPcrEvent) Digests() *[]PCRDigestValue {
	d := make([]PCRDigestValue, 1)
	d[0].DigestAlg = TPMAlgSha
	d[0].Digest = make([]byte, TPMAlgShaSize)
	copy(d[0].Digest, e.digest[:])

	return &d
}

func (e *TcgPcrEvent) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "PCR: %d\n", e.PcrIndex())
	fmt.Fprintf(&b, "Event Name: %s\n", e.PcrEventName())
	fmt.Fprintf(&b, "Event Data: %s\n", stripControlSequences(e.PcrEventData()))
	fmt.Fprintf(&b, "SHA1 Digest: %x", e.digest)

	return b.String()
}


// type TcgPcrEvent2 struct {
// 	pcrIndex  uint32
// 	eventType uint32
// 	digests   LDigestValues
// 	eventSize uint32
// 	event     []byte
// }
func parseTcgPcrEvent2(handle io.Reader) (*TcgPcrEvent2, error) {
	var endianess binary.ByteOrder = binary.LittleEndian
	var pcrEvent TcgPcrEvent2

	if err := binary.Read(handle, endianess, &pcrEvent.pcrIndex); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, endianess, &pcrEvent.eventType); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, endianess, &pcrEvent.digests.count); err != nil {
		return nil, err
	}

	pcrEvent.digests.digests = make([]THA, pcrEvent.digests.count)
	for i := uint32(0); i < pcrEvent.digests.count; i++ {
		if err := binary.Read(handle, endianess, &pcrEvent.digests.digests[i].hashAlg); err != nil {
			return nil, err
		}

		pcrEvent.digests.digests[i].digest.hash = make([]byte, HashAlgoToSize[pcrEvent.digests.digests[i].hashAlg])
		if err := binary.Read(handle, endianess, &pcrEvent.digests.digests[i].digest.hash); err != nil {
			return nil, err
		}
	}

	if err := binary.Read(handle, endianess, &pcrEvent.eventSize); err != nil {
		return nil, err
	}

	pcrEvent.event = make([]byte, pcrEvent.eventSize)
	if err := binary.Read(handle, endianess, &pcrEvent.event); err != nil {
		return nil, err
	}

	return &pcrEvent, nil
}

func (e *TcgPcrEvent2) PcrIndex() int {
	return int(e.pcrIndex)
}

func (e *TcgPcrEvent2) PcrEventName() string {
	if BIOSLogTypes[BIOSLogID(e.eventType)] != "" {
		return BIOSLogTypes[BIOSLogID(e.eventType)]
	}
	if EFILogTypes[EFILogID(e.eventType)] != "" {
		return EFILogTypes[EFILogID(e.eventType)]
	}

	return ""
}

func (e *TcgPcrEvent2) PcrEventData() string {
	if BIOSLogID(e.eventType) == EvNoAction {
		return string(e.event)
	} else {
		eventDataString, _ := getEventDataString(e.eventType, e.event)
		if eventDataString != nil {
			return *eventDataString
		}
	}

	return ""
}

func (e *TcgPcrEvent2) Digests() *[]PCRDigestValue {
	d := make([]PCRDigestValue, e.digests.count)
	for i := uint32(0); i < e.digests.count; i++ {
		d[i].DigestAlg = e.digests.digests[i].hashAlg
		d[i].Digest = make([]byte, HashAlgoToSize[e.digests.digests[i].hashAlg])
		copy(d[i].Digest, e.digests.digests[i].digest.hash)
	}
	return &d
}

func (e *TcgPcrEvent2) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "PCR: %d\n", e.PcrIndex())
	fmt.Fprintf(&b, "Event Name: %s\n", e.PcrEventName())
	fmt.Fprintf(&b, "Event Data: %s\n", stripControlSequences(e.PcrEventData()))
	for i := uint32(0); i < e.digests.count; i++ {
		d := &e.digests.digests[i]
		switch d.hashAlg {
		case TPMAlgSha:
			b.WriteString("SHA1 Digest: ")
		case TPMAlgSha256:
			b.WriteString("SHA256 Digest: ")
		case TPMAlgSha384:
			b.WriteString("SHA384 Digest: ")
		case TPMAlgSha512:
			b.WriteString("SHA512 Digest: ")
		case TPMAlgSm3s256:
			b.WriteString("SM3 Digest: ")
		}

		fmt.Fprintf(&b, "%x", d.digest.hash)
	}

	return b.String()
}
