# Security

gelada is a security boundary, so a way around it is a vulnerability: a
sandboxed program reading a denied path, writing outside the allowed
folders, reaching the network when it is off, seeing a filtered variable, or
running unsandboxed.

**Please report privately**, through GitHub's
[private vulnerability reporting](https://github.com/addiscorp/gelada/security/advisories/new),
not in a public issue. Include the platform and version (macOS version, or
Linux kernel and distribution), and the smallest program that shows the
escape.

We'll confirm within a few days, fix it, and credit you in the advisory
unless you'd rather not be named.

Things the README's threat model lists as out of scope (damage inside
allowed folders, the network once it is on, kernel exploits) are not
vulnerabilities, but ideas for narrowing them are welcome as issues.
