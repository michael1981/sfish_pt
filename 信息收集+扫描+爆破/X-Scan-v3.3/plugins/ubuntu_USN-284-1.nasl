# This script was automatically generated from the 284-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21569);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "284-1");
script_summary(english:"quagga vulnerabilities");
script_name(english:"USN284-1 : quagga vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- quagga 
- quagga-doc 
');
script_set_attribute(attribute:'description', value: 'Paul Jakma discovered that Quagga\'s ripd daemon did not properly
handle authentication of RIPv1 requests. If the RIPv1 protocol had
been disabled, or authentication for RIPv2 had been enabled, ripd
still replied to RIPv1 requests, which could lead to information
disclosure. (CVE-2006-2223)

Paul Jakma also noticed that ripd accepted unauthenticated RIPv1
response packets if RIPv2 was configured to require authentication and
both protocols were allowed. A remote attacker could exploit this to
inject arbitrary routes. (CVE-2006-2224)

Fredrik Widell discovered that Quagga did not properly handle certain
invalid \'sh ip bgp\' commands. By sending special commands to Quagga, a
remote attacker with telnet access to the Quagga server could exploit
this to trigger an endless loop in the daemon (Denial of Service).
(CVE-2006-2276)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- quagga-0.99.1-1ubuntu1.1 (Ubuntu 5.10)
- quagga-doc-0.99.1-1ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2006-2223","CVE-2006-2224","CVE-2006-2276");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "quagga", pkgver: "0.99.1-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package quagga-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to quagga-0.99.1-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "quagga-doc", pkgver: "0.99.1-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package quagga-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to quagga-doc-0.99.1-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
