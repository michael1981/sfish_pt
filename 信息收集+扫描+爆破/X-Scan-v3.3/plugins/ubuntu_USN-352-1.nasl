# This script was automatically generated from the 352-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27932);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "352-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN352-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious email containing JavaScript. Please note that JavaScript
is disabled by default for emails, and it is not recommended to enable
it. (CVE-2006-4253, CVE-2006-4565, CVE-2006-4566, CVE-2006-4571)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Jon Oberheide reported a way how a remote attacker could trick users
into downloading arbitrary extensions with circumventing the normal
SSL certificate check. The attacker would have to be in a position to
spoof the victim\'s DNS, causing them to connect to sites of the
attacker\'s choosing rather than the sites intended by the victim. If
they gained that control and the victim accepted the attacker\'s cert
for the Mozi
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.7-0ubuntu0.6.06 (Ubuntu 6.06)
- mozilla-thunderbird-dev-1.5.0.7-0ubuntu0.6.06 (Ubuntu 6.06)
- mozilla-thunderbird-inspector-1.5.0.7-0ubuntu0.6.06 (Ubuntu 6.06)
- mozilla-thunderbird-typeaheadfind-1.5.0.7-0ubuntu0.6.06 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-4253","CVE-2006-4340","CVE-2006-4565","CVE-2006-4566","CVE-2006-4567","CVE-2006-4570","CVE-2006-4571");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.7-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-1.5.0.7-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.7-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-dev-1.5.0.7-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.7-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-inspector-1.5.0.7-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.7-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.7-0ubuntu0.6.06
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
