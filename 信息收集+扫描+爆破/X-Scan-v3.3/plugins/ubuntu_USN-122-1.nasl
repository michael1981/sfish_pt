# This script was automatically generated from the 122-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20511);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "122-1");
script_summary(english:"squid vulnerability");
script_name(english:"USN122-1 : squid vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- squid 
- squid-cgi 
- squid-common 
- squidclient 
');
script_set_attribute(attribute:'description', value: 'Michael Bhola discovered that errors in the http_access configuration,
in particular missing or invalid ACLs, did not cause a fatal error.
This could lead to wider access permissions than intended by the
administrator.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- squid-2.5.8-3ubuntu1.1 (Ubuntu 5.04)
- squid-cgi-2.5.8-3ubuntu1.1 (Ubuntu 5.04)
- squid-common-2.5.8-3ubuntu1.1 (Ubuntu 5.04)
- squidclient-2.5.8-3ubuntu1.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1345");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "squid", pkgver: "2.5.8-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-2.5.8-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squid-cgi", pkgver: "2.5.8-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-cgi-2.5.8-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squid-common", pkgver: "2.5.8-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-common-2.5.8-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squidclient", pkgver: "2.5.8-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squidclient-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squidclient-2.5.8-3ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
