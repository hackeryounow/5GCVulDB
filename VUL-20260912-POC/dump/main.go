// Temporary ground-truth dumper: prints the exact NGAP/NAS bytes produced by
// the free5gc builders (copied verbatim from ../main.go) so the Python port can
// be validated byte-for-byte. Deleted after the port is verified.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func encodePLMN(mcc, mnc string) ngapType.PLMNIdentity {
	b := make([]byte, 3)
	b[0] = (mcc[1]-'0')<<4 | (mcc[0] - '0')
	if len(mnc) == 2 {
		b[1] = 0xf0 | (mcc[2] - '0')
		b[2] = (mnc[1]-'0')<<4 | (mnc[0] - '0')
	} else {
		b[1] = (mnc[2]-'0')<<4 | (mcc[2] - '0')
		b[2] = (mnc[1]-'0')<<4 | (mnc[0] - '0')
	}
	return ngapType.PLMNIdentity{Value: aper.OctetString(b)}
}

func encodeTAC(tac uint64) ngapType.TAC {
	tacBytes, _ := hex.DecodeString(fmt.Sprintf("%06x", tac))
	return ngapType.TAC{Value: aper.OctetString(tacBytes)}
}

func plmnBCD(mcc, mnc string) []byte {
	b := make([]byte, 3)
	b[0] = (mcc[1]-'0')<<4 | (mcc[0] - '0')
	if len(mnc) == 2 {
		b[1] = 0xf0 | (mcc[2] - '0')
		b[2] = (mnc[1]-'0')<<4 | (mnc[0] - '0')
	} else {
		b[1] = (mnc[2]-'0')<<4 | (mcc[2] - '0')
		b[2] = (mnc[1]-'0')<<4 | (mnc[0] - '0')
	}
	return b
}

func suciMobileIdentity(mcc, mnc, msin string, routing string) []byte {
	out := []byte{0x01}
	out = append(out, plmnBCD(mcc, mnc)...)
	ri, _ := hex.DecodeString(routing)
	out = append(out, ri...)
	out = append(out, 0x00)
	out = append(out, 0x00)
	for i := 0; i < len(msin); i += 2 {
		lo := msin[i] - '0'
		hi := msin[i+1] - '0'
		out = append(out, lo|(hi<<4))
	}
	return out
}

func buildRegistrationRequest(mcc, mnc, msin string, sst byte, sd string) []byte {
	nas := []byte{0x7e, 0x00, 0x41}
	nas = append(nas, 0x79)
	mid := suciMobileIdentity(mcc, mnc, msin, "0000")
	nas = append(nas, byte(len(mid)>>8), byte(len(mid)))
	nas = append(nas, mid...)
	nas = append(nas, 0x2e, 0x04, 0xf0, 0xf0, 0xf0, 0xf0)
	sdB, _ := hex.DecodeString(sd)
	nas = append(nas, 0x2f, 0x05, 0x04, sst, sdB[0], sdB[1], sdB[2])
	return nas
}

func buildAuthResponseRES(resLen int) []byte {
	nas := []byte{0x7e, 0x00, 0x57}
	nas = append(nas, 0x2d, byte(resLen))
	for i := 0; i < resLen; i++ {
		nas = append(nas, 0x42)
	}
	return nas
}

func buildAuthFailureAUTS(autsLen int) []byte {
	nas := []byte{0x7e, 0x00, 0x59}
	nas = append(nas, 0x15)
	nas = append(nas, 0x30, byte(autsLen))
	for i := 0; i < autsLen; i++ {
		nas = append(nas, 0x41)
	}
	return nas
}

func buildNGSetupRequest(mcc, mnc string, tac uint64, gnbId uint32, sst byte, sd string) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentNGSetupRequest
	im.Value.NGSetupRequest = new(ngapType.NGSetupRequest)
	req := im.Value.NGSetupRequest
	{
		ie := ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDGlobalRANNodeID
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentGlobalRANNodeID
		ie.Value.GlobalRANNodeID = new(ngapType.GlobalRANNodeID)
		grni := ie.Value.GlobalRANNodeID
		grni.Present = ngapType.GlobalRANNodeIDPresentGlobalGNBID
		grni.GlobalGNBID = new(ngapType.GlobalGNBID)
		grni.GlobalGNBID.PLMNIdentity = encodePLMN(mcc, mnc)
		grni.GlobalGNBID.GNBID.Present = ngapType.GNBIDPresentGNBID
		grni.GlobalGNBID.GNBID.GNBID = new(aper.BitString)
		grni.GlobalGNBID.GNBID.GNBID.Bytes = []byte{byte(gnbId >> 24), byte(gnbId >> 16), byte(gnbId >> 8), byte(gnbId)}
		grni.GlobalGNBID.GNBID.GNBID.BitLength = 32
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDSupportedTAList
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentSupportedTAList
		ie.Value.SupportedTAList = new(ngapType.SupportedTAList)
		bplmn := ngapType.BroadcastPLMNItem{}
		bplmn.PLMNIdentity = encodePLMN(mcc, mnc)
		ssItem := ngapType.SliceSupportItem{}
		ssItem.SNSSAI.SST.Value = aper.OctetString{sst}
		if sd != "" {
			sdB, _ := hex.DecodeString(sd)
			ssItem.SNSSAI.SD = new(ngapType.SD)
			ssItem.SNSSAI.SD.Value = aper.OctetString(sdB)
		}
		bplmn.TAISliceSupportList.List = append(bplmn.TAISliceSupportList.List, ssItem)
		taItem := ngapType.SupportedTAItem{}
		taItem.TAC = encodeTAC(tac)
		taItem.BroadcastPLMNList.List = append(taItem.BroadcastPLMNList.List, bplmn)
		ie.Value.SupportedTAList.List = append(ie.Value.SupportedTAList.List, taItem)
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.NGSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDDefaultPagingDRX
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.NGSetupRequestIEsPresentDefaultPagingDRX
		ie.Value.DefaultPagingDRX = new(ngapType.PagingDRX)
		ie.Value.DefaultPagingDRX.Value = ngapType.PagingDRXPresentV32
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	return ngap.Encoder(pdu)
}

func buildInitialUEMessage(mcc, mnc string, tac uint64, ranUeNgapID int64, nasPdu []byte) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeInitialUEMessage
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentInitialUEMessage
	im.Value.InitialUEMessage = new(ngapType.InitialUEMessage)
	req := im.Value.InitialUEMessage
	{
		ie := ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentRANUENGAPID
		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
		ie.Value.RANUENGAPID.Value = ranUeNgapID
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDNASPDU
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentNASPDU
		ie.Value.NASPDU = new(ngapType.NASPDU)
		ie.Value.NASPDU.Value = nasPdu
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentUserLocationInformation
		ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)
		uli := ie.Value.UserLocationInformation
		uli.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
		uli.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)
		uli.UserLocationInformationNR.NRCGI.PLMNIdentity = encodePLMN(mcc, mnc)
		uli.UserLocationInformationNR.NRCGI.NRCellIdentity.Value = aper.BitString{
			Bytes: []byte{0x00, 0x00, 0x00, 0x01, 0x00}, BitLength: 36}
		uli.UserLocationInformationNR.TAI.PLMNIdentity = encodePLMN(mcc, mnc)
		uli.UserLocationInformationNR.TAI.TAC = encodeTAC(tac)
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRRCEstablishmentCause
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentRRCEstablishmentCause
		ie.Value.RRCEstablishmentCause = new(ngapType.RRCEstablishmentCause)
		ie.Value.RRCEstablishmentCause.Value = ngapType.RRCEstablishmentCausePresentMoSignalling
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	return ngap.Encoder(pdu)
}

func buildUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeUplinkNASTransport
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentUplinkNASTransport
	im.Value.UplinkNASTransport = new(ngapType.UplinkNASTransport)
	req := im.Value.UplinkNASTransport
	{
		ie := ngapType.UplinkNASTransportIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.UplinkNASTransportIEsPresentAMFUENGAPID
		ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
		ie.Value.AMFUENGAPID.Value = amfUeNgapID
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.UplinkNASTransportIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.UplinkNASTransportIEsPresentRANUENGAPID
		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
		ie.Value.RANUENGAPID.Value = ranUeNgapID
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	{
		ie := ngapType.UplinkNASTransportIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDNASPDU
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.UplinkNASTransportIEsPresentNASPDU
		ie.Value.NASPDU = new(ngapType.NASPDU)
		ie.Value.NASPDU.Value = nasPdu
		req.ProtocolIEs.List = append(req.ProtocolIEs.List, ie)
	}
	return ngap.Encoder(pdu)
}

func main() {
	const (
		mcc   = "208"
		mnc   = "95"
		msin  = "0000000031"
		tac   = uint64(0xa000)
		sst   = byte(222)
		sd    = "00007b"
		gnbId = uint32(0x0adead)
	)
	regReq := buildRegistrationRequest(mcc, mnc, msin, sst, sd)
	fmt.Printf("NAS_REG_REQ %s\n", hex.EncodeToString(regReq))
	fmt.Printf("NAS_AUTH_RES %s\n", hex.EncodeToString(buildAuthResponseRES(200)))
	fmt.Printf("NAS_AUTH_FAIL %s\n", hex.EncodeToString(buildAuthFailureAUTS(200)))

	ng, _ := buildNGSetupRequest(mcc, mnc, tac, gnbId, sst, sd)
	fmt.Printf("NGSETUP %s\n", hex.EncodeToString(ng))

	iue, _ := buildInitialUEMessage(mcc, mnc, tac, 1, regReq)
	fmt.Printf("INITIAL_UE %s\n", hex.EncodeToString(iue))

	ul, _ := buildUplinkNASTransport(1, 1, buildAuthResponseRES(200))
	fmt.Printf("UPLINK_NAS %s\n", hex.EncodeToString(ul))

	ul2, _ := buildUplinkNASTransport(0x1234, 1, buildAuthResponseRES(200))
	fmt.Printf("UPLINK_NAS_AMFID_0x1234 %s\n", hex.EncodeToString(ul2))
}
