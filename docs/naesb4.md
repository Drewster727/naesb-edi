# NAESB WGQ EDM Version 4.0 Architectural & Technical Specification
## Engineering & Integration Implementation Guide

This document defines the technical, cryptographic, transport, and metadata requirements for implementing a data exchange solution compliant with the **North American Energy Standards Board (NAESB) Wholesale Gas Quadrant (WGQ) Electronic Delivery Mechanism (EDM) Version 4.0** standards. It is intended for systems architects and software engineers developing custom B2B interfaces or integration pipelines to communicate directly with interstate natural gas pipeline operators.

---

## 1. Architectural Model & Topology

The NAESB 4.0 EDM standard utilizes a synchronous, peer-to-peer client-server communication topology operating over secure internet infrastructure. Unlike standard retail or supply-chain EDI networks that leverage commercial Value Added Networks (VANs), NAESB 4.0 mandates direct **Internet Electronic Transport (Internet ET)**.

---

## 2. Cryptographic & Security Requirements (OpenPGP)

NAESB WGQ Version 4.0 deprecates all legacy cryptographic configurations—including 3DES symmetric encryption, MD5, and SHA-1 hashing/digest algorithms. All transactions must adhere strictly to the **OpenPGP (RFC 4880)** standard.

### Cryptographic Primitive Constraints
* **Asymmetric Key Algorithm:** Rivest–Shamir–Adleman (RSA).
* **Minimum Key Length:** 2048-bit required; **4096-bit** is highly recommended and mandated by modern pipeline infrastructures.
* **Symmetric Encryption Cipher:** **AES-256** (Advanced Encryption Standard with a 256-bit key length).
* **Hash / Message Digest Algorithm:** **SHA-256** or higher (Secure Hash Algorithm 2, 256-bit digest size).

### Outbound Payload Processing Sequence
Before transmission via the transport layer, the outbound payload (typically an ANSI X12 file) must execute the following atomic cryptographic pipeline:

1. **Compression:** The raw payload string is compressed using standard PGP ZIP or ZLIB compression.
2. **Signature Application:** The compressed payload is signed using the sender's private PGP key, computing the hash with a **SHA-256** digest.
3. **Encryption Envelope:** The signed, compressed payload is encrypted using the recipient pipeline's public PGP key utilizing the **AES-256** symmetric cipher block.
4. **Binary Stream Extraction:** The resulting armor-less, raw binary payload is passed directly to the transport client.

---

## 3. Transport Protocol & HTTP POST Constraints

The transport layer requires an HTTP client capable of low-level header injection and explicit manipulation of the transport-layer handshake parameters.

### Transport Layer Security (TLS)
* All connections must utilize **TLS 1.2** or **TLS 1.3**.
* Connections attempting a handshake over SSL v2, SSL v3, TLS 1.0, or TLS 1.1 must be rejected.

### HTTP Request Profile
* **HTTP Method:** `POST`
* **Content-Type Header:** `application/octet-stream` (Mandatory for binary payload passing; text/html or multipart/form-data formats will result in pipeline gateway parsing faults).
* **Header Case-Sensitivity:** **Strictly Lowercase**. Standard HTTP header normalization (e.g., Pascal-Case headers like `From-Id`) deviates from the NAESB specification; headers must be injected in absolute lowercase format.

### Mandated NAESB Request HTTP Headers

| Header Key | Expected Data Type / Format | Technical Description |
| :--- | :--- | :--- |
| `version` | String (e.g., `4.0`) | Specifies the exact NAESB WGQ Electronic Delivery Mechanism baseline version. |
| `from-id` | 9-Digit Numeric String | The Data Universal Numbering System (**DUNS**) number of the sending entity (your gateway or client's ID). |
| `to-id` | 9-Digit Numeric String | The **DUNS** number identifying the targeted gas pipeline operator. |
| `input-format` | Enumerated String (`X12`, `XML`, `FLATFILE`) | Identifies the formatting syntax of the underlying decrypted payload. |
| `transaction-set` | 3-Digit Numeric String (e.g., `873`) | The ANSI ASC X12 Transaction Set identifier mapping the business logic (see Section 5). |

### Wire-Level Request Simulation
```http
POST /edi/receiver-endpoint HTTP/1.1
Host: secure-transport.interstate-pipeline.com
Content-Type: application/octet-stream
User-Agent: Enterprise-NAESB-Client/4.0
Content-Length: 4822

version: 4.0
from-id: 123456789
to-id: 987654321
input-format: X12
transaction-set: 873

[... Raw Binary AES-256 / OpenPGP Encrypted Blob Data ...]

4. Synchronous Response Receipt Handling
Unlike standard commercial protocols that handle message non-repudiation asynchronously or synchronously via an X.509 wrapped Message Disposition Notification (MDN), NAESB 4.0 enforces a distinct synchronous response model inside the HTTP 200 OK return loop.

Response Pipeline Flow
When your system transmits an HTTP POST to a pipeline, the connection must remain open while the pipeline's gateway validates the payload envelope. The server returns a custom textual metadata response containing explicit confirmation attributes.

Technical Requirements of the Response
Cryptographic Validation: The text payload returned in the body of the HTTP 200 OK response is OpenPGP-signed by the pipeline using their private key. Your code must capture this stream and verify the signature against the pipeline's public key using SHA-256 to ensure authenticity.

Metadata Parsing: Once verified and decrypted, the response payload must be parsed (typically standard line-delimited key-value formats) to evaluate transmission success.

Key NAESB Response Metadata Parameters
receipt-status: Evaluates to success or validation-failed.

receipt-timestamp: The precise UTC timestamp applied by the pipeline's clock boundary proving timely submission (critical for strict nomination deadlines).

error-code / error-description: Standardized integer codes defining structural errors (e.g., 101: Decryption Failed, 102: Signature Verification Failed, 103: Invalid Header Parameters).

5. Core Wholesale Gas Quadrant Data Transactions
Once the transport and cryptographic envelopes are successfully executed, the inner payload is routed to a translation engine. For the Wholesale Gas Quadrant, your translation maps must support the following essential ANSI ASC X12 transaction sets:

EDI 873 - Nomination: Submitted by your client to the pipeline to reserve pipeline capacity and dictate gas injection/withdrawal points.

EDI 861 - Scheduled Quantity: Transmitted by the pipeline back to your system, detailing the confirmed volumes of gas scheduled to flow based on nomination matching.

EDI 811 - Consolidated Invoice: Pipeline billing data sent to your clients detailing transportation charges, fuel retention balances, and usage fees.

EDI 824 - Application Advice: A technical response indicating whether an underlying business document failed internal data integrity validations or contract matching rules.

6. Network Topology & Infrastructure Considerations
Static Routing Requirements: Interstate pipelines operate under rigid federal utility security regulations. They do not permit dynamic ingress or elastic IP pools (such as standard dynamic cloud provider blocks). All connections must route out of dedicated, static egress IPs whitelisted by the pipeline.

Technical Exchange Worksheet (TEW): Prior to entering the pipeline certification testing loop, your infrastructure engineering team must compile a TEW. This document exchanges the fixed client/server URLs, w