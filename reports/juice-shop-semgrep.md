# SAST report: OWASP Juice Shop

Generated 2026-10-09 · Tools: semgrep · Findings: 92

## Summary

| OWASP 2025 category | Critical | High | Medium | Low | Info | Total |
| --- | --- | --- | --- | --- | --- | --- |
| A01:2025 Broken Access Control | 0 | 0 | 6 | 0 | 0 | 6 |
| A03:2025 Software Supply Chain Failures | 0 | 0 | 7 | 0 | 0 | 7 |
| A04:2025 Cryptographic Failures | 0 | 0 | 17 | 0 | 0 | 17 |
| A05:2025 Injection | 0 | 29 | 0 | 0 | 0 | 29 |
| A06:2025 Insecure Design | 0 | 1 | 4 | 0 | 0 | 5 |
| A07:2025 Authentication Failures | 0 | 3 | 12 | 0 | 0 | 15 |
| A08:2025 Software or Data Integrity Failures | 0 | 0 | 2 | 0 | 0 | 2 |
| A10:2025 Mishandling of Exceptional Conditions | 0 | 0 | 1 | 0 | 0 | 1 |
| Unmapped | 0 | 0 | 6 | 0 | 4 | 10 |

## A01:2025 Broken Access Control

### [MEDIUM] express-open-redirect

- **Where:** `target/juice-shop/routes/redirect.ts` line 18
- **Rule:** `javascript.express.security.audit.express-open-redirect.express-open-redirect` (semgrep) · **CWE:** CWE-601
- **What:** The application redirects to a URL specified by user-supplied input `query` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate URLs, or warn users they are being redirected to a third-party website.

### [MEDIUM] express-check-directory-listing

- **Where:** `target/juice-shop/server.ts` line 268
- **Rule:** `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` (semgrep) · **CWE:** CWE-548
- **What:** Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

### [MEDIUM] express-check-directory-listing

- **Where:** `target/juice-shop/server.ts` line 288
- **Rule:** `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` (semgrep) · **CWE:** CWE-548
- **What:** Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

### [MEDIUM] express-check-directory-listing

- **Where:** `target/juice-shop/server.ts` line 292
- **Rule:** `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` (semgrep) · **CWE:** CWE-548
- **What:** Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

### [MEDIUM] express-check-directory-listing

- **Where:** `target/juice-shop/server.ts` line 296
- **Rule:** `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` (semgrep) · **CWE:** CWE-548
- **What:** Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

### [MEDIUM] express-check-directory-listing

- **Where:** `target/juice-shop/server.ts` line 300
- **Rule:** `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` (semgrep) · **CWE:** CWE-548
- **What:** Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

## A03:2025 Software Supply Chain Failures

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/ci.yml` line 188
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/codeql-analysis.yml` line 23
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/codeql-analysis.yml` line 34
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/codeql-analysis.yml` line 36
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/image_actions.yml` line 30
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/image_actions.yml` line 33
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

### [MEDIUM] github-actions-mutable-action-tag

- **Where:** `target/juice-shop/.github/workflows/image_actions.yml` line 42
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` (semgrep) · **CWE:** CWE-1357, CWE-353
- **What:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

## A04:2025 Cryptographic Failures

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/data/datacreator.ts` line 305
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/data/datacreator.ts` line 323
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/data/datacreator.ts` line 381
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/data/datacreator.ts` line 755
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/frontend/src/app/Services/conversation-storage.service.ts` line 17
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/frontend/src/app/chatbot/chat-welcome-screen/chat-welcome-screen.component.ts` line 71
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/frontend/src/app/coding-challenge-page/components/coding-challenge-fix-it/coding-challenge-fix-it.component.ts` line 120
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] insecure-load-balancer-tls-version

- **Where:** `target/juice-shop/infrastructure/terraform/networking.tf` line 160
- **Rule:** `terraform.aws.security.insecure-load-balancer-tls-version.insecure-load-balancer-tls-version` (semgrep) · **CWE:** CWE-326
- **What:** Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"`, or include a default action to redirect to HTTPS.

### [MEDIUM] node_md5

- **Where:** `target/juice-shop/lib/insecurity.ts` line 41
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_md5` (semgrep) · **CWE:** CWE-327
- **What:** MD5 is a a weak hash which is known to have collision. Use a strong hashing function.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/lib/insecurity.ts` line 53
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/routes/captcha.ts` line 14
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/routes/captcha.ts` line 15
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/routes/captcha.ts` line 16
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/routes/captcha.ts` line 18
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_insecure_random_generator

- **Where:** `target/juice-shop/routes/captcha.ts` line 19
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator` (semgrep) · **CWE:** CWE-327
- **What:** crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.

### [MEDIUM] node_md5

- **Where:** `target/juice-shop/scripts/package.mjs` line 121
- **Rule:** `ajinabraham.njsscan.crypto.crypto_node.node_md5` (semgrep) · **CWE:** CWE-327
- **What:** MD5 is a a weak hash which is known to have collision. Use a strong hashing function.

### [MEDIUM] insecure-load-balancer-tls-version

- **Where:** `target/juice-shop/terraform/networking.tf` line 160
- **Rule:** `terraform.aws.security.insecure-load-balancer-tls-version.insecure-load-balancer-tls-version` (semgrep) · **CWE:** CWE-326
- **What:** Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"`, or include a default action to redirect to HTTPS.

## A05:2025 Injection

### [HIGH] gha-curl-pipe-shell

- **Where:** `target/juice-shop/.github/workflows/ci.yml` line 359
- **Rule:** `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` (semgrep) · **CWE:** CWE-78
- **What:** A `run:` step pipes the output of `curl` or `wget` directly into a shell interpreter. This is the "curl | bash" install pattern — if the remote server is compromised or the URL is hijacked, an attacker can execute arbitrary code in your CI runner. Consider downloading the file first, verifying its checksum or signature, and then executing it.

### [HIGH] run-shell-injection

- **Where:** `target/juice-shop/.github/workflows/update-challenges-ebook.yml` line 22
- **Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection` (semgrep) · **CWE:** CWE-78
- **What:** Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

### [HIGH] run-shell-injection

- **Where:** `target/juice-shop/.github/workflows/update-challenges-www-legacy.yml` line 27
- **Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection` (semgrep) · **CWE:** CWE-78
- **What:** Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

### [HIGH] run-shell-injection

- **Where:** `target/juice-shop/.github/workflows/update-challenges-www-legacy.yml` line 36
- **Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection` (semgrep) · **CWE:** CWE-78
- **What:** Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

### [HIGH] run-shell-injection

- **Where:** `target/juice-shop/.github/workflows/update-challenges-www.yml` line 27
- **Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection` (semgrep) · **CWE:** CWE-78
- **What:** Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

### [HIGH] run-shell-injection

- **Where:** `target/juice-shop/.github/workflows/update-challenges-www.yml` line 36
- **Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection` (semgrep) · **CWE:** CWE-78
- **What:** Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/address.ts` line 18
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/basket.ts` line 19
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/basketItems.ts` line 68
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/captcha.ts` line 37
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/dataErasure.ts` line 34
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/delivery.ts` line 34
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/deluxe.ts` line 19
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/deluxe.ts` line 25
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/deluxe.ts` line 35
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/likeProductReviews.ts` line 25
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/likeProductReviews.ts` line 43
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] express-sequelize-injection

- **Where:** `target/juice-shop/routes/login.ts` line 34
- **Rule:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` (semgrep) · **CWE:** CWE-89
- **What:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/order.ts` line 35
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/order.ts` line 125
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/order.ts` line 148
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/payment.ts` line 41
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] express-sequelize-injection

- **Where:** `target/juice-shop/routes/search.ts` line 23
- **Rule:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` (semgrep) · **CWE:** CWE-89
- **What:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

### [HIGH] node_nosqli_js_injection

- **Where:** `target/juice-shop/routes/showProductReviews.ts` line 31
- **Rule:** `ajinabraham.njsscan.database.nosql_injection.node_nosqli_js_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in MongoDB $where operator can result in NoSQL JavaScript Injection.

### [HIGH] node_nosqli_js_injection

- **Where:** `target/juice-shop/routes/trackOrder.ts` line 15
- **Rule:** `ajinabraham.njsscan.database.nosql_injection.node_nosqli_js_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in MongoDB $where operator can result in NoSQL JavaScript Injection.

### [HIGH] express_xss

- **Where:** `target/juice-shop/routes/userProfile.ts` line 34
- **Rule:** `ajinabraham.njsscan.xss.xss_node.express_xss` (semgrep) · **CWE:** CWE-79
- **What:** Untrusted User Input in Response will result in Reflected Cross Site Scripting Vulnerability.

### [HIGH] code-string-concat

- **Where:** `target/juice-shop/routes/userProfile.ts` line 65
- **Rule:** `javascript.lang.security.audit.code-string-concat.code-string-concat` (semgrep) · **CWE:** CWE-95
- **What:** Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/wallet.ts` line 12
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

### [HIGH] node_nosqli_injection

- **Where:** `target/juice-shop/routes/wallet.ts` line 24
- **Rule:** `ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection` (semgrep) · **CWE:** CWE-943
- **What:** Untrusted user input in findOne() function can result in NoSQL Injection.

## A06:2025 Insecure Design

### [HIGH] node_logic_bypass

- **Where:** `target/juice-shop/routes/verify.ts` line 60
- **Rule:** `ajinabraham.njsscan.generic.logic_bypass.node_logic_bypass` (semgrep) · **CWE:** CWE-807
- **What:** User controlled data is used for application business logic decision making. This expose protected data or functionality.

### [MEDIUM] express-res-sendfile

- **Where:** `target/juice-shop/routes/fileServer.ts` line 32
- **Rule:** `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` (semgrep) · **CWE:** CWE-73
- **What:** The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

### [MEDIUM] express-res-sendfile

- **Where:** `target/juice-shop/routes/keyServer.ts` line 14
- **Rule:** `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` (semgrep) · **CWE:** CWE-73
- **What:** The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

### [MEDIUM] express-res-sendfile

- **Where:** `target/juice-shop/routes/logfileServer.ts` line 14
- **Rule:** `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` (semgrep) · **CWE:** CWE-73
- **What:** The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

### [MEDIUM] express-res-sendfile

- **Where:** `target/juice-shop/routes/quarantineServer.ts` line 14
- **Rule:** `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` (semgrep) · **CWE:** CWE-73
- **What:** The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

## A07:2025 Authentication Failures

### [HIGH] node_password

- **Where:** `target/juice-shop/frontend/src/app/login/login.component.ts` line 63
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_password` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded password in plain text is identified. Store it properly in an environment variable.

### [HIGH] node_password

- **Where:** `target/juice-shop/frontend/src/app/register/register.component.spec.ts` line 137
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_password` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded password in plain text is identified. Store it properly in an environment variable.

### [HIGH] node_password

- **Where:** `target/juice-shop/frontend/src/app/register/register.component.spec.ts` line 138
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_password` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded password in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/data/datacreator.ts` line 350
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/data/datacreator.ts` line 354
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/login/login.component.ts` line 62
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/navbar/navbar.component.spec.ts` line 562
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts` line 56
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts` line 66
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/sidenav/sidenav.component.spec.ts` line 236
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/sidenav/sidenav.component.spec.ts` line 250
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] node_username

- **Where:** `target/juice-shop/frontend/src/app/sidenav/sidenav.component.spec.ts` line 382
- **Rule:** `ajinabraham.njsscan.generic.hardcoded_secrets.node_username` (semgrep) · **CWE:** CWE-798
- **What:** A hardcoded username in plain text is identified. Store it properly in an environment variable.

### [MEDIUM] hardcoded-jwt-secret

- **Where:** `target/juice-shop/lib/insecurity.ts` line 54
- **Rule:** `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` (semgrep) · **CWE:** CWE-798
- **What:** A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

### [MEDIUM] express_cors

- **Where:** `target/juice-shop/server.ts` line 182
- **Rule:** `ajinabraham.njsscan.headers.header_cors_star.express_cors` (semgrep) · **CWE:** CWE-346
- **What:** Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions.

### [MEDIUM] generic_cors

- **Where:** `target/juice-shop/server.ts` line 182
- **Rule:** `ajinabraham.njsscan.headers.header_cors_star.generic_cors` (semgrep) · **CWE:** CWE-346
- **What:** Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions.

## A08:2025 Software or Data Integrity Failures

### [MEDIUM] npm-missing-minimum-release-age

- **Where:** `target/juice-shop/.npmrc` line 1
- **Rule:** `package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age` (semgrep) · **CWE:** CWE-829
- **What:** This .npmrc does not set a minimum release age or sets it too low. Newly published packages can be malicious or unstable. Add `min-release-age = 7` to wait 7 days before resolving newly published package versions. Added in: v11.10 Reference: https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/

### [MEDIUM] npm-missing-minimum-release-age

- **Where:** `target/juice-shop/frontend/.npmrc` line 1
- **Rule:** `package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age` (semgrep) · **CWE:** CWE-829
- **What:** This .npmrc does not set a minimum release age or sets it too low. Newly published packages can be malicious or unstable. Add `min-release-age = 7` to wait 7 days before resolving newly published package versions. Added in: v11.10 Reference: https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/

## A10:2025 Mishandling of Exceptional Conditions

### [MEDIUM] generic_error_disclosure

- **Where:** `target/juice-shop/rsn/rsnUtil.ts` line 63
- **Rule:** `ajinabraham.njsscan.generic.error_disclosure.generic_error_disclosure` (semgrep) · **CWE:** CWE-209
- **What:** Error messages with stack traces may expose sensitive information about the application.

## Unmapped

### [MEDIUM] node_timing_attack

- **Where:** `target/juice-shop/frontend/src/app/change-password/change-password.component.ts` line 139
- **Rule:** `ajinabraham.njsscan.crypto.timing_attack_node.node_timing_attack` (semgrep) · **CWE:** CWE-208
- **What:** String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. A timing attack allows the attacker to learn potentially sensitive information by, for example, measuring how long it takes for the application to respond to a request. More info: https://nodejs.org/en/learn/getting-started/security-best-practices#information-exposure-through-timing-attacks-cwe-208

### [MEDIUM] node_timing_attack

- **Where:** `target/juice-shop/frontend/src/app/forgot-password/forgot-password.component.ts` line 140
- **Rule:** `ajinabraham.njsscan.crypto.timing_attack_node.node_timing_attack` (semgrep) · **CWE:** CWE-208
- **What:** String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. A timing attack allows the attacker to learn potentially sensitive information by, for example, measuring how long it takes for the application to respond to a request. More info: https://nodejs.org/en/learn/getting-started/security-best-practices#information-exposure-through-timing-attacks-cwe-208

### [MEDIUM] node_timing_attack

- **Where:** `target/juice-shop/frontend/src/app/register/register.component.ts` line 109
- **Rule:** `ajinabraham.njsscan.crypto.timing_attack_node.node_timing_attack` (semgrep) · **CWE:** CWE-208
- **What:** String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. A timing attack allows the attacker to learn potentially sensitive information by, for example, measuring how long it takes for the application to respond to a request. More info: https://nodejs.org/en/learn/getting-started/security-best-practices#information-exposure-through-timing-attacks-cwe-208

### [MEDIUM] aws-subnet-has-public-ip-address

- **Where:** `target/juice-shop/infrastructure/terraform/networking.tf` line 18
- **Rule:** `terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address` (semgrep) · **CWE:** CWE-1220
- **What:** Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

### [MEDIUM] node_timing_attack

- **Where:** `target/juice-shop/routes/changePassword.ts` line 28
- **Rule:** `ajinabraham.njsscan.crypto.timing_attack_node.node_timing_attack` (semgrep) · **CWE:** CWE-208
- **What:** String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. A timing attack allows the attacker to learn potentially sensitive information by, for example, measuring how long it takes for the application to respond to a request. More info: https://nodejs.org/en/learn/getting-started/security-best-practices#information-exposure-through-timing-attacks-cwe-208

### [MEDIUM] aws-subnet-has-public-ip-address

- **Where:** `target/juice-shop/terraform/networking.tf` line 18
- **Rule:** `terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address` (semgrep) · **CWE:** CWE-1220
- **What:** Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

### [INFO] helmet_header_nosniff

- **Where:** `target/juice-shop/server.ts` line 186
- **Rule:** `ajinabraham.njsscan.good.good_helmet_checks.helmet_header_nosniff` (semgrep) · **CWE:** none
- **What:** Content-Type-Options header is present. More information: https://helmetjs.github.io/docs/dont-sniff-mimetype/

### [INFO] helmet_header_frame_guard

- **Where:** `target/juice-shop/server.ts` line 187
- **Rule:** `ajinabraham.njsscan.good.good_helmet_checks.helmet_header_frame_guard` (semgrep) · **CWE:** none
- **What:** X-Frame-Options header is present. More information: https://helmetjs.github.io/docs/frameguard/

### [INFO] helmet_header_x_powered_by

- **Where:** `target/juice-shop/server.ts` line 189
- **Rule:** `ajinabraham.njsscan.good.good_helmet_checks.helmet_header_x_powered_by` (semgrep) · **CWE:** none
- **What:** Default X-Powered-By is removed or modified. More information: https://helmetjs.github.io/docs/hide-powered-by/

### [INFO] helmet_header_feature_policy

- **Where:** `target/juice-shop/server.ts` line 190
- **Rule:** `ajinabraham.njsscan.good.good_helmet_checks.helmet_header_feature_policy` (semgrep) · **CWE:** none
- **What:** Feature-Policy header is present. More information: https://helmetjs.github.io/docs/feature-policy/
