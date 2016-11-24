# This script was automatically generated from the 350-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27930);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "350-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN350-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-enigmail 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-locale-ca 
- mozilla-thunderbird-locale-de 
- mozilla-thunderbird-locale-fr 
- mozilla-thunderbird-locale-it 
- mozilla-thunderbird-locale-nl 
- mozilla-thunderbird-locale-pl 
- mozilla-thunderbird-locale-uk 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'This update upgrades Thunderbird from 1.0.8 to 1.5.0.7. This step was
necessary since the 1.0.x series is not supported by upstream any
more.

Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious email containing JavaScript. Please note that JavaScript
is disabled by default for emails, and it is not recommended to enable
it. (CVE-2006-3113, CVE-2006-3802, CVE-2006-3803, CVE-2006-3805,
CVE-2006-3806, CVE-2006-3807, CVE-2006-3809, CVE-2006-3810,
CVE-2006-3811, CVE-2006-3812, CVE-2006-4253, CVE-2006-4565,
CVE-2006-4566, CVE-2006-4571)

A buffer overflow has been discovered in the handling of .vcard files.
By tricking a user into importing a malicious vcard into his contacts,
this could be exploited to execute arbitrary code with the user\'s
privileges.  (CVE-2006-3804)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for C
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.7-0ubuntu0.5.10 (Ubuntu 5.10)
- mozilla-thunderbird-dev-1.5.0.7-0ubuntu0.5.10 (Ubuntu 5.10)
- mozilla-thunderbird-enigmail-0.94-0ubuntu0.5.10 (Ubuntu 5.10)
- mozilla-thunderbird-inspector-1.5.0.7-0ubuntu0.5.10 (Ubuntu 5.10)
- mozilla-thunderbird-locale-ca-1.5-ubuntu5.10 (Ubuntu 5.10)
- mozilla-thunderbird-locale-de-1.5-ubuntu5.10 (Ubuntu 5.10)
- mozilla-thunderbird-locale-fr-1.5-ubuntu5.10 (Ubuntu 5.10)
- mozilla-thunderbird-locale-it-1.5-ubuntu5.10 (Ubuntu 5.10)
-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-3113","CVE-2006-3802","CVE-2006-3803","CVE-2006-3804","CVE-2006-3805","CVE-2006-3806","CVE-2006-3807","CVE-2006-3809","CVE-2006-3810","CVE-2006-3811","CVE-2006-3812","CVE-2006-4253","CVE-2006-4340","CVE-2006-4565","CVE-2006-4566","CVE-2006-4567","CVE-2006-4570","CVE-2006-4571");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.7-0ubuntu0.5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-1.5.0.7-0ubuntu0.5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.7-0ubuntu0.5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-dev-1.5.0.7-0ubuntu0.5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.94-0ubuntu0.5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-enigmail-0.94-0ubuntu0.5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.7-0ubuntu0.5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-inspector-1.5.0.7-0ubuntu0.5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-ca", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-ca-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-ca-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-de", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-de-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-de-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-fr", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-fr-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-fr-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-it", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-it-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-it-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-nl", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-nl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-nl-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-pl", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-pl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-pl-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-locale-uk", pkgver: "1.5-ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-locale-uk-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-locale-uk-1.5-ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.7-0ubuntu0.5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.7-0ubuntu0.5.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
