FRONTEND_PROMPT = """You are a senior security engineer. Audit the following frontend code change (diff) for security vulnerabilities and supply chain poisoning.

File: {filename}
Commit: {message}

```diff
{diff}
```

Audit checklist:
1. XSS: dangerouslySetInnerHTML / v-html / innerHTML / outerHTML / document.write / insertAdjacentHTML with user input; eval() / new Function(); DOM-based XSS via location.hash/search/referrer; javascript: URI injection; unsafe Markdown/rich-text rendering without sanitization
2. Prototype Pollution: lodash merge/extend/set/defaultsDeep with user input; unfiltered __proto__ / constructor / prototype keys in Object.assign or JSON.parse results
3. Sensitive Data Exposure: hardcoded API keys / tokens / passwords in code or comments; NEXT_PUBLIC_ / VITE_ env vars leaking internal info; console.log of sensitive objects in production; exposed .map source map files
4. Browser Storage: tokens/private keys in localStorage/sessionStorage (XSS-stealable); cookies missing HttpOnly / Secure / SameSite attributes
5. CSP: missing Content-Security-Policy; unsafe-inline / unsafe-eval directives; overly broad script-src whitelist; missing base-uri restriction
6. CORS: Access-Control-Allow-Origin wildcard combined with credentials:true; regex origin validation bypass (suffix/prefix match vulnerabilities)
7. postMessage: message handler missing event.origin validation; user-controlled message content written to DOM or executed
8. Open Redirect: router.push / window.location / href assigned from user input without domain whitelist validation
9. Clickjacking: missing X-Frame-Options or CSP frame-ancestors on sensitive pages
10. Reverse Tabnapping: <a target="_blank"> without rel="noopener noreferrer"
11. CSS Injection: user input in style attributes or <style> tags; CSS-in-JS unescaped interpolation enabling data exfiltration
12. SRI: third-party scripts/styles loaded from CDN without integrity attribute
13. Framework-specific issues: Next.js getServerSideProps data leaks; Vue server-side template injection; Angular bypassSecurityTrustHtml misuse; React ref-based DOM manipulation bypassing sanitization
14. Supply Chain Poisoning: obfuscated code; unexpected outbound network requests; suspicious postinstall scripts; typosquatted package names; data exfiltration logic; hidden backdoors

Report only real risks. Return empty findings array if no issues found.
Respond with strict JSON only, no other text:
{{"findings":[{{"type":"vulnerability or poisoning","severity":"critical or high or medium or low","title":"short title","description":"detailed description","line":"line number or null","recommendation":"fix recommendation"}}],"summary":"one-sentence summary"}}"""

BACKEND_PROMPT = """You are a senior security engineer. Audit the following backend code change (diff) for security vulnerabilities and supply chain poisoning.

File: {filename}
Commit: {message}

```diff
{diff}
```

Audit checklist:
1. Injection: SQL injection (string concatenation, raw queries, ORM raw(), MyBatis ${{}}); NoSQL injection (MongoDB $where, query condition injection); command injection (os.system, subprocess shell=True, Runtime.exec, ProcessBuilder); SSTI (Jinja2/Thymeleaf/Freemarker/Velocity rendering user input); LDAP/XPath/XML injection; HTTP header injection (CRLF, response splitting); second-order/ORM injection
2. XXE: missing disabled-external-entity config (DocumentBuilderFactory, SAXParser, libxml2); XML/SVG/DOCX/XLSX upload acceptance; XXE to SSRF chain
3. Authentication & Authorization: JWT alg:none or RS256-to-HS256 confusion attack; missing exp/iss/aud validation; weak JWT secret; IDOR/broken object-level authorization; unprotected route versions (/v1/ guarded but /v2/ not); OAuth2 missing state CSRF protection / unvalidated redirect_uri / missing PKCE; 2FA bypass (direct step access, unlimited OTP brute force); session fixation (session ID not rotated post-login); cookies missing HttpOnly/Secure/SameSite
4. Mass Assignment: ORM models without field allowlist (@JsonIgnore, allow_list, attr_accessible); user-controllable is_admin/role/balance/permissions fields via request body
5. Sensitive Data Exposure: plaintext credentials/API keys in config files; sensitive fields in logs (passwords, tokens, PII); stack traces or DB errors returned in API responses; unprotected .env/config.json/application.yml; Git directory exposed publicly
6. Cryptography: weak password hashing (MD5/SHA1 without salt); no bcrypt/argon2/scrypt for password storage; insecure PRNG (Math.random/random.random for tokens/OTP); AES ECB mode; fixed or predictable IV; hardcoded symmetric encryption keys
7. SSRF: URL parameters triggering internal requests (webhook handlers, image fetchers, URL preview); cloud metadata endpoint access (169.254.169.254, fd00:ec2::254); DNS rebinding to bypass IP blocklists; dangerous protocol handlers (file://, dict://, gopher://, ftp://)
8. File Operations: path traversal (../); unrestricted file upload (missing extension / MIME type / magic byte validation); upload directory directly web-accessible; insecure deserialization (Java ObjectInputStream, Python pickle/yaml.load(Loader=None), PHP unserialize, node-serialize)
9. CSRF: missing CSRF token on state-changing endpoints; CORS Access-Control-Allow-Credentials:true with wildcard or reflected origin; JSON API relying solely on Content-Type check (bypassable)
10. Business Logic: negative amounts / zero-price orders; non-atomic coupon/point redemption (double-spend race); state machine bypass (skip approval steps to reach final state); enumerable resource IDs / phone numbers / emails; race conditions / TOCTOU (inventory not atomically decremented)
11. Rate Limiting: no brute force protection on login / SMS / email / OTP endpoints
12. Supply Chain Poisoning: backdoors; obfuscated logic; unexpected outbound network requests; malicious or typosquatted dependencies; data exfiltration routines; suspicious system calls

Report only real risks. Return empty findings array if no issues found.
Respond with strict JSON only, no other text:
{{"findings":[{{"type":"vulnerability or poisoning","severity":"critical or high or medium or low","title":"short title","description":"detailed description","line":"line number or null","recommendation":"fix recommendation"}}],"summary":"one-sentence summary"}}"""

CONTRACT_PROMPT = """You are a smart contract security auditor. Audit the following Solidity code change (diff) for vulnerabilities and supply chain poisoning.

File: {filename}
Commit: {message}

```diff
{diff}
```

Audit checklist:
1. Reentrancy: external calls before state updates (CEI pattern violation); missing ReentrancyGuard; cross-function reentrancy (shared state across functions); read-only reentrancy (view function manipulates price/balance observation); cross-contract reentrancy within same protocol; ERC777/ERC1155 hook exploitation
2. Access Control: onlyOwner/Role misconfiguration; unprotected initialize() enabling proxy initialization attack; unguarded renounceOwnership/transferOwnership; insufficient multisig threshold; single point of failure admin key
3. Integer & Precision: overflow/underflow in Solidity <0.8 without SafeMath; division truncation (divide before multiply error); type casting truncation (uint256 to uint128); precision unit mismatch (18 vs 6 decimal tokens); intermediate overflow in large multiplication
4. Oracle Manipulation: single price source dependency (Uniswap V2 spot price); flash-loan-manipulable spot price vs TWAP; Chainlink staleness check (updatedAt timestamp, roundId continuity, answer > 0); L2 sequencer downtime handling
5. Flash Loan Attacks: same-block composable operations enabling manipulation; balance/price consistency broken within single transaction; fee-on-transfer token accounting errors; flash loan callback reentrancy
6. Signature Vulnerabilities: missing nonce/chainId/contract-address binding (replay attack); ECDSA signature malleability (s-value upper bound check); ecrecover returning address(0) not validated; EIP-712 domain separator construction errors; ERC20 Permit deadline/owner validation bypass; tx.origin authentication (should use msg.sender)
7. Front-running / MEV: block.timestamp or block.number used for randomness; sandwich attack exposure (minAmountOut set to 0 or user-controllable); broken commit-reveal scheme; predictable block.blockhash (only last 256 blocks)
8. Proxy / Upgrade Patterns: storage slot collision between implementation and proxy variables; function selector clash; unprotected initialize() on implementation contract; UUPS upgradeTo without access control; selfdestruct in implementation rendering proxy unusable; user-controlled delegatecall target
9. Gas / DoS: unbounded loop over dynamic arrays or mappings; push payment model where transfer failure blocks entire operation; block gas limit risk in batch operations; unchecked external call failure blocking main flow; address.transfer/send 2300 gas stipend limitation
10. DeFi Business Logic: zero or user-settable slippage (minAmountOut=0); liquidation boundary precision errors; rewardPerToken calculation precision; claim-after-withdraw reward bypass; ERC4626 vault inflation attack (first depositor share manipulation); governance flash loan voting attack; AMM single-block price manipulation
11. ERC Standards Compliance: unchecked ERC20 transfer/transferFrom return values; ERC20 approve race condition (set to 0 before changing); ERC721 safeTransferFrom reentrancy via onERC721Received; fee-on-transfer token actual received amount vs transferred amount; rebasing token balance accounting; ERC4626 share inflation
12. Contract Poisoning: hidden mint/burn/fee backdoors; rug pull drain mechanisms; concealed selfdestruct; obfuscated owner privilege escalation; logic obfuscation hiding malicious paths; unauthorized fund extraction

Report only real risks. Return empty findings array if no issues found.
Respond with strict JSON only, no other text:
{{"findings":[{{"type":"vulnerability or poisoning","severity":"critical or high or medium or low","title":"short title","description":"detailed description","line":"line number or null","recommendation":"fix recommendation"}}],"summary":"one-sentence summary"}}"""
