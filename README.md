# eapreach - reach each & preach

**Reach each EAP packet. Discover configuration reality. Preach configuration compliance.**

A powerful, client-side **802.1X/EAP packet analyzer** with integrated certificate validation. Understand what really happens during enterprise Wi-Fi and Ethernet authentication.

---

## What is eapreach?

`eapreach` is a **tshark-based EAP analyzer** that runs directly on your client device during authentication. Unlike traditional packet sniffing from a separate machine, eapreach shows you the **client perspective** of the entire EAP handshake in real-time.

### Why is this useful?

| Scenario | eapreach helps by... |
|----------|----------------------|
| **Troubleshooting 802.1X failures** | Shows exactly where auth breaks (Identity? Certificate? TLS handshake?) |
| **Testing different EAP methods** | Validate EAP-TLS, EAP-TTLS, PEAP, MD5-Challenge side-by-side |
| **Certificate validation** | Automatically detects self-signed certs, issuer chains, expiration dates |
| **Security auditing** | Identifies deprecated methods (MD5), downgrade attacks (Legacy NAK), MITM risks |
| **Network compliance** | Verify corporate security policies are actually enforced |
| **Device testing** | Check if a specific device supports modern EAP methods |

---

## How it works

```
CLIENT (running eapreach)
    ↓
    ├─ Initiates 802.1X/EAP authentication
    ├─ eapreach captures EAPOL/EAP frames in real-time
    ├─ Decodes EAP method, certificate details, TLS handshake
    ├─ Flags security warnings (deprecated, downgrade, self-signed)
    └─ Shows: Success ✓ or Failure ✗

AUTHENTICATOR (AP/Switch) ← Backend RADIUS (not visible to eapreach)
    ↓
    └─ Server-side auth (invisible from client perspective)
```

**Key point:** eapreach shows what the **client sees**, not backend RADIUS communication.
