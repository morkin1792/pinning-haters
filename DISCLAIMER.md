# Disclaimer

pinning-haters is a security-testing tool. It disables a protection that app developers put in
place on purpose. Read this before installing it.

## Authorised use only

Use it only on apps and accounts you own or are explicitly authorised to test, on devices you
control. Intercepting the traffic of an app or a user without authorisation may be a criminal offence
in your jurisdiction regardless of your intent. You are responsible for knowing and following the law
and the terms of any engagement you work under.

## It weakens the apps you point it at

While a package is listed in the configuration, that app will accept **any** TLS certificate chain
from **any** server, not just your proxy's. Do not leave production accounts, payment credentials or
personal data in a targeted app on a device you also use day to day, and remove packages from the
configuration when you are done with them. The module does nothing to apps that are not listed.

## Not for malicious use

The project refuses features that only make sense for malicious use: covert payload injection,
persistence beyond what the module itself needs, data exfiltration, or any outbound network traffic.
Requests for such features will be declined, and forks that add them are not endorsed.

## No warranty

This software is licensed under the GNU General Public License, version 3 or later, and is provided
**without any warranty**, express or implied, including the warranties of merchantability and fitness
for a particular purpose. It modifies the runtime state of other processes on a rooted device. It can
crash apps, slow them down (see `docs/known-limitations.md`), interfere with other root modules, or
fail to do anything at all. Keep backups. The authors and contributors accept no liability for damage,
data loss, account lockouts, detection by an app's anti-tamper logic, or any other consequence of
installing or using it.

## Pre-release software

As of v0.2.0 the module has been verified on two physical devices (Android 11 and Android 16), not
on the full release matrix. See the Status section of the README and `docs/testing.md` before
relying on it.
