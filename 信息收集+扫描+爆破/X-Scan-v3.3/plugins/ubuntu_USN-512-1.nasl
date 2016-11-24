# This script was automatically generated from the 512-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28117);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "512-1");
script_summary(english:"Quagga vulnerability");
script_name(english:"USN512-1 : Quagga vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- quagga 
- quagga-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Quagga did not correctly verify OPEN messages or
COMMUNITY attributes sent from configured peers. Malicious authenticated
remote peers could send a specially crafted message which would cause
bgpd to abort, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- quagga-0.99.6-2ubuntu3.2 (Ubuntu 7.04)
- quagga-doc-0.99.6-2ubuntu3.2 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4826");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "quagga", pkgver: "0.99.6-2ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package quagga-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to quagga-0.99.6-2ubuntu3.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "quagga-doc", pkgver: "0.99.6-2ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package quagga-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to quagga-doc-0.99.6-2ubuntu3.2
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
