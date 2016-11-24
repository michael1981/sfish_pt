# This script was automatically generated from the 329-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27908);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "329-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN329-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-enigmail 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious email containing JavaScript. Please note that JavaScript
is disabled by default for emails, and it is not recommended to enable
it. (CVE-2006-3113, CVE-2006-3802, CVE-2006-3803, CVE-2006-3805,
CVE-2006-3806, CVE-2006-3807, CVE-2006-3809, CVE-2006-3810,
CVE-2006-3811, CVE-2006-3812)

A buffer overflow has been discovered in the handling of .vcard files.
By tricking a user into importing a malicious vcard into his contacts,
this could be exploited to execute arbitrary code with the user\'s
privileges.  (CVE-2006-3084)

The "enigmail" plugin has been updated to work with the new
Thunderbird version.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.5-0ubuntu0.6.06 (Ubuntu 6.06)
- mozilla-thunderbird-dev-1.5.0.5-0ubuntu0.6.06 (Ubuntu 6.06)
- mozilla-thunderbird-enigmail-0.94-0ubuntu4.2 (Ubuntu 6.06)
- mozilla-thunderbird-inspector-1.5.0.5-0ubuntu0.6.06 (Ubuntu 6.06)
- mozilla-thunderbird-typeaheadfind-1.5.0.5-0ubuntu0.6.06 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3084","CVE-2006-3113","CVE-2006-3802","CVE-2006-3803","CVE-2006-3804","CVE-2006-3805","CVE-2006-3806","CVE-2006-3807","CVE-2006-3809","CVE-2006-3810","CVE-2006-3811","CVE-2006-3812");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.5-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-1.5.0.5-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.5-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-dev-1.5.0.5-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.94-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-enigmail-0.94-0ubuntu4.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.5-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-inspector-1.5.0.5-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.5-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.5-0ubuntu0.6.06
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
