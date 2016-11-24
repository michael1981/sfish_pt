# This script was automatically generated from the 441-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28038);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "441-1");
script_summary(english:"Squid vulnerability");
script_name(english:"USN441-1 : Squid vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- squid 
- squid-cgi 
- squid-common 
- squidclient 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in Squid\'s handling of the TRACE request method 
which could lead to a crash.  Remote attackers with access to the Squid 
server could send malicious TRACE requests, and cause a denial of 
service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- squid-2.6.1-3ubuntu1.3 (Ubuntu 6.10)
- squid-cgi-2.6.1-3ubuntu1.3 (Ubuntu 6.10)
- squid-common-2.6.1-3ubuntu1.3 (Ubuntu 6.10)
- squidclient-2.6.1-3ubuntu1.3 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1560");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "squid", pkgver: "2.6.1-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to squid-2.6.1-3ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "squid-cgi", pkgver: "2.6.1-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to squid-cgi-2.6.1-3ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "squid-common", pkgver: "2.6.1-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to squid-common-2.6.1-3ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "squidclient", pkgver: "2.6.1-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squidclient-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to squidclient-2.6.1-3ubuntu1.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
