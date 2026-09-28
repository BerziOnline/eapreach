# eapreach

**reach each** & **preach**

Reach each EAP packet. Discover configuration reality. Preach configuration compliance.

eapreach shows the 802.1X/EAP authentication of a client, packet by packet, and flags weak configurations. It is one bash script on top of `tshark` and reads a pcap file or captures live.

```
Frame  | EAPOL      | EAP           | Code     | Interesting
------ | ---------- | ------------- | -------- | ==================================================
3      | EAP Packet | Identity      | Response | Identity: anonymous
4      | EAP Packet | MD5-Challenge | Request  | Server offers MD5-Challenge ⚠ [WEAK-METHOD]
5      | EAP Packet | Legacy Nak    | Response | Client refused method ⚠ [DOWNGRADE-POSSIBLE]
10     | EAP Packet | PEAP          | Request  | TLS: Server Hello(2)
       |            |               |          | TLS: Certificate(11)
       |            |               |          | ┌ CERTIFICATE (server):
       |            |               |          |   CN: notebook34 ⚠ [SELF-SIGNED]
       |            |               |          |   Issuer: notebook34
       |            |               |          |   Valid: 2025-01-13 20:40:40 (UTC) to 2035-01-11 20:40:40 (UTC)
       |            |               |          | └
20     | EAP Packet |               | Failure  | ✗ FAIL
```

## Usage

```bash
./eapreach.sh capture.pcapng    # analyze a pcap/pcapng file
./eapreach.sh -i eth0           # live capture (as root or as user, sudo is used if needed)
./eapreach.sh -h                # help and all warnings explained
```

Run it on the 802.1X client while it authenticates (LAN port or WLAN). Switch the client's EAP method one by one and watch what the network answers. After a live capture you can keep the full pcap for later analysis.

RADIUS traffic (switch/AP to AAA server) is not visible from the client and therefore not part of eapreach.

## Requirements

- Linux, bash 4.3+
- tshark (Debian/Ubuntu: `apt install tshark`)
- grep, sed, awk, xargs, coreutils, iproute2 (present on any common distribution)
- Live capture: root or sudo

## Warnings

| Warning | Meaning | Fix |
|---|---|---|
| `WEAK-METHOD` | MD5-Challenge, OTP, GTC or LEAP. No server authentication, no keys. A captured MD5/LEAP answer can be cracked offline. | Disable these methods on the RADIUS server |
| `DOWNGRADE-POSSIBLE` | Legacy Nak: the server accepts method negotiation. A client that allows a weaker method gets it, and a Nak can be forged (RFC 3748, 7.8). | Allow only the methods you need |
| `SELF-SIGNED` | Server certificate signed by itself, typically the untouched default of the RADIUS server or device. Users learn to accept any certificate, including a rogue access point's. | Certificate from your own CA, roll out the CA, enforce validation on the clients |
| `CERT-EXPIRED` `CERT-NOT-YET-VALID` | Certificate not valid at capture time | Re-issue |
| `WEAK-SIGNATURE` `WEAK-KEY` | Certificate signed with MD5/SHA-1, or RSA key below 2048 bit | Re-issue |
| `OLD-TLS-VERSION` `WEAK-CIPHER` | TLS 1.1 or older, or RC4/DES/3DES/NULL/EXPORT/anon cipher | TLS 1.2+ with modern ciphers |
| `IDENTITY-EXPOSED` | Outer identity is a real username | Anonymous outer identity on the client |
| `NO-METHOD` | EAP-Success without any authentication method | Check port and RADIUS policy for fail-open or accept-all rules |

## Tested methods

| Method | Status |
|---|---|
| MD5-Challenge | ✅ |
| PEAP | ✅ |
| EAP-TTLS | ✅ |
| EAP-TLS (TLS 1.2) | ✅ server and client certificate |
| EAP-TLS (TLS 1.3) | ✅ certificates are encrypted in TLS 1.3 and cannot be shown |
| EAP-FAST | ✅ |
| TEAP | ❔ not tested |

Only the unencrypted part is visible: the inner authentication of PEAP/TTLS/FAST/TEAP runs inside the TLS tunnel. eapreach shows which certificate the server presents, not whether the client checks it.

## Screenrecords

<details>
<summary>Help</summary>

![Help](records/help.gif)
</details>

<details>
<summary>Live capture (no live data during recording)</summary>

![Live capture](records/live_capture%20%28sadly%20no%20live-data%20available%29.gif)
</details>

<details>
<summary>MD5, success</summary>

![MD5](records/MD5_1xSuccess.gif)
</details>

<details>
<summary>EAP-TTLS, failure</summary>

![EAP-TTLS](records/EAP-TTLS_1xFail.gif)
</details>

<details>
<summary>EAP-TTLS, 3x success, 1x failure</summary>

![EAP-TTLS multiple](records/EAP-TTLS_3xSuccess_1xFail.gif)
</details>

<details>
<summary>PEAP, failure</summary>

![PEAP](records/PEAP_1xFail.gif)
</details>

The pcaps of these recordings are in `pcaps/`.

## Disclaimer

Capture only on networks you own or are allowed to test.

## License

MIT, see [LICENSE](LICENSE).
