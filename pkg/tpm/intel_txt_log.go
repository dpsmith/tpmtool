package tpm

import (
	"encoding/binary"
	"io"
	"os"
)

func (e TxtLogID) String() string {
	switch e {
	case TxtEvTypeBase:
		return "EVTYPE_BASE"
	case TxtEvTypePcrMapping:
		return "EVTYPE_PCRMAPPING"
	case TxtEvTypeHashStart:
		return "EVTYPE_HASH_START"
	case TxtEvTypeCombinedHash:
		return "EVTYPE_COMBINED_HASH"
	case TxtEvTypeMleHash:
		return "EVTYPE_MLE_HASH"
	case TxtEvTypeBiosAcRegData:
		return "EVTYPE_BIOSAC_REG_DATA"
	case TxtEvTypeCpuScrtmStat:
		return "EVTYPE_CPU_SCRTM_STAT"
	case TxtEvTypeLcpControlHash:
		return "EVTYPE_LCP_CONTROL_HASH"
	case TxtEvTypeElementsHash:
		return "EVTYPE_ELEMENTS_HASH"
	case TxtEvTypeStmHash:
		return "EVTYPE_STM_HASH"
	case TxtEvTypeOsSinitDataCapHash:
		return "EVTYPE_OSSINITDATA_CAP_HASH"
	case TxtEvTypeSinitPubKeyHash:
		return "EVTYPE_SINIT_PUBKEY_HASH"
	case TxtEvTypeLcpHash:
		return "EVTYPE_LCP_HASH"
	case TxtEvTypeLcpDetailsHash:
		return "EVTYPE_LCP_DETAILS_HASH"
	case TxtEvTypeLcpAuthoritiesHash:
		return "EVTYPE_LCP_AUTHORITIES_HASH"
	case TxtEvTypeNvInfoHash:
		return "EVTYPE_NV_INFO_HASH"
	case TxtEvTypeColdBootBiosHash:
		return "EVTYPE_COLD_BOOT_BIOS_HASH"
	case TxtEvTypeKmHash:
		return "EVTYPE_KM_HASH"
	case TxtEvTypeBpmHash:
		return "EVTYPE_BPM_HASH"
	case TxtEvTypeKmInfoHash:
		return "EVTYPE_KM_INFO_HASH"
	case TxtEvTypeBpmInfoHash:
		return "EVTYPE_BPM_INFO_HASH"
	case TxtEvTypeBootPolHash:
		return "EVTYPE_BOOT_POL_HASH"
	case TxtEvTypeCapValue:
		return "EVTYPE_CAP_VALUE"
	}
	return ""
}

func readTxtEventLogContainer(handle io.Reader) (*TxtEventLogContainer, error) {
	var container TxtEventLogContainer

	if err := binary.Read(handle, binary.LittleEndian, &container.Signature); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.Reserved); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.ContainerVerMajor); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.ContainerVerMinor); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.PcrEventVerMajor); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.PcrEventVerMinor); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.Size); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.PcrEventsOffset); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &container.NextEventOffset); err != nil {
		return nil, err
	}

	return &container, nil
}

func parseTxt12Log(file *os.File) (*PCRLog, error) {
	var pcrLog PCRLog

	container, err := readTxtEventLogContainer(file)
	if err != nil {
		return nil, err
	}

	// seek to first PCR event
	file.Seek(int64(container.PcrEventsOffset), os.SEEK_SET)

	for {
		var offset int64

		offset, err = file.Seek(0, os.SEEK_CUR)
		if err != nil {
			return nil, err
		}

		if offset >= int64(container.NextEventOffset) {
			break
		}

		var pcrEvent *TcgPcrEvent

		pcrEvent, err = parseTcgPcrEvent(file)
		if err != nil {
			return nil, err
		}

		pcrLog.PcrList = append(pcrLog.PcrList, pcrEvent)
	}

	return &pcrLog, nil
}

func parseTxtHeapEventLogDescr(handle io.Reader) (*TxtHeapEventLogDescr, error) {
	var descr TxtHeapEventLogDescr

	if err := binary.Read(handle, binary.LittleEndian, &descr.Alg); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &descr.Reserved); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &descr.PhysAddr); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &descr.Size); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &descr.PcrEventsOffset); err != nil {
		return nil, err
	}
	if err := binary.Read(handle, binary.LittleEndian, &descr.NextEventOffset); err != nil {
		return nil, err
	}

	return &descr, nil
}
