# Security Policy

Warden is a security package, so we take vulnerabilities in it especially
seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report them privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/sellinnate/warden/security/advisories/new)
- Email: **security@selli.io**

Please include:

- a description of the vulnerability and its impact;
- steps to reproduce (a failing test or a concrete input string is ideal);
- the affected version(s) and your environment.

We aim to acknowledge reports within **72 hours** and to ship a fix or mitigation
for confirmed issues as quickly as is responsible, coordinating disclosure with
you.

## Scope and expectations

Warden is a **risk-mitigation** layer, not a guarantee. The deterministic core is
a high-precision *first filter*; it does not claim to catch every novel,
paraphrased, or multi-turn attack (those are the domain of the optional AI
drivers and of your own defence-in-depth). Reports that demonstrate a **bypass of
a control Warden advertises** (e.g. a normalization evasion, a redaction leak, a
defang bypass, a checksum false-accept, a ReDoS) are in scope and very welcome.

"The deterministic layer didn't catch a brand-new semantic jailbreak" is a known
and documented limitation, not a vulnerability — but a corpus contribution that
adds it is still appreciated.

## Disclosure philosophy

We practice coordinated disclosure and will credit reporters (unless you prefer
to remain anonymous) in the changelog and release notes.
