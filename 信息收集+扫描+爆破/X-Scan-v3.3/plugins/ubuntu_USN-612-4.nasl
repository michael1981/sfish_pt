# This script was automatically generated from the 612-4 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32358);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "612-4");
script_summary(english:"ssl-cert vulnerability");
script_name(english:"USN612-4 : ssl-cert vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "ssl-cert" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-612-1 fixed vulnerabilities in openssl.  This update provides the
corresponding updates for ssl-cert -- potentially compromised snake-oil
SSL certificates will be regenerated.

Original advisory details:

 A weakness has been discovered in the random number generator used
 by OpenSSL on Debian and Ubuntu systems.  As a result of this
 weakness, certain encryption keys are much more common than they
 should be, such that an attacker could guess the key through a
 brute-force attack given minimal knowledge of the system.  This
 particularly affects the use of encryption keys in OpenSSH, OpenVPN
 and SSL certificates.
 
 This vulnerability only affects operating systems which (like
 Ubuntu) are based on Debian.  However, other systems can be
 indirectly affected if weak keys are imported into them.
 
 We consider this an extremely serious vulnerability, and urge all
 users to act immediately to secure their systems. (CVE-2008-0166)
 
 == Who is affected ==
 
 Systems which are running any of the following r
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ssl-cert-1.0.14-0ubuntu2.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2008-0166");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "ssl-cert", pkgver: "1.0.14-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssl-cert-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ssl-cert-1.0.14-0ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
