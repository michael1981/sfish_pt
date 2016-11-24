# This script was automatically generated from the 221-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20763);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "221-1");
script_summary(english:"ipsec-tools vulnerability");
script_name(english:"USN221-1 : ipsec-tools vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ipsec-tools 
- racoon 
');
script_set_attribute(attribute:'description', value: 'The Oulu University Secure Programming Group discovered a remote
Denial of Service vulnerability in the racoon daemon. When the daemon
is configured to use aggressive mode, then it did not check whether
the peer sent all required payloads during the IKE negotiation phase.
A malicious IPsec peer could exploit this to crash the racoon daemon.

Please be aware that racoon is not officially supported by Ubuntu, the
package is in the \'universe\' component of the archive.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ipsec-tools-0.6-1ubuntu1.1 (Ubuntu 5.10)
- racoon-0.6-1ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2005-3732");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "ipsec-tools", pkgver: "0.6-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ipsec-tools-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ipsec-tools-0.6-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "racoon", pkgver: "0.6-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package racoon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to racoon-0.6-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
