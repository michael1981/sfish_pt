# This script was automatically generated from the 400-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27988);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "400-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN400-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'Georgi Guninski and David Bienvenu discovered that long Content-Type and 
RFC2047-encoded headers we vulnerable to heap overflows.  By tricking 
the user into opening a specially crafted email, an attacker could 
execute arbitrary code with user privileges.  (CVE-2006-6506)

Various flaws have been reported that allow an attacker to execute 
arbitrary code with user privileges or bypass internal XSS protections 
by tricking the user into opening a malicious email containing 
JavaScript.  Please note that JavaScript is disabled by default for 
emails, and it is not recommended to enable it.  (CVE-2006-6497, 
CVE-2006-6498, CVE-2006-6499, CVE-2006-6501, CVE-2006-6502, 
CVE-2006-6503)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.9-0ubuntu0.6.10 (Ubuntu 6.10)
- mozilla-thunderbird-dev-1.5.0.9-0ubuntu0.6.10 (Ubuntu 6.10)
- mozilla-thunderbird-inspector-1.5.0.9-0ubuntu0.6.10 (Ubuntu 6.10)
- mozilla-thunderbird-typeaheadfind-1.5.0.9-0ubuntu0.6.10 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-6497","CVE-2006-6498","CVE-2006-6499","CVE-2006-6501","CVE-2006-6502","CVE-2006-6503","CVE-2006-6505","CVE-2006-6506");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-1.5.0.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-dev-1.5.0.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-inspector-1.5.0.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.9-0ubuntu0.6.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
