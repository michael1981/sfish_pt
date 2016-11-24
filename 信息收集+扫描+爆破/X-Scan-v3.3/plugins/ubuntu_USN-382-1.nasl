# This script was automatically generated from the 382-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27965);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "382-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN382-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'USN-352-1 fixed a flaw in the verification of PKCS certificate 
signatures. Ulrich Kuehn discovered a variant of the original attack 
which the original fix did not cover. (CVE-2006-5462)

Various flaws have been reported that allow an attacker to execute 
arbitrary code with user privileges by tricking the user into opening a 
malicious email containing JavaScript. Please note that JavaScript is 
disabled by default for emails, and it is not recommended to enable it. 
(CVE-2006-5463, CVE-2006-5464, CVE-2006-5747, CVE-2006-5748)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.8-0ubuntu0.6.10 (Ubuntu 6.10)
- mozilla-thunderbird-dev-1.5.0.8-0ubuntu0.6.10 (Ubuntu 6.10)
- mozilla-thunderbird-inspector-1.5.0.8-0ubuntu0.6.10 (Ubuntu 6.10)
- mozilla-thunderbird-typeaheadfind-1.5.0.8-0ubuntu0.6.10 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5462","CVE-2006-5463","CVE-2006-5464","CVE-2006-5747","CVE-2006-5748");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.8-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-1.5.0.8-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.8-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-dev-1.5.0.8-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.8-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-inspector-1.5.0.8-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.8-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.8-0ubuntu0.6.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
