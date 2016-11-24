# This script was automatically generated from the 844-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42079);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "844-1");
script_summary(english:"mimetex vulnerabilities");
script_name(english:"USN844-1 : mimetex vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mimetex" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Chris Evans discovered that mimeTeX incorrectly handled certain long tags.
An attacker could exploit this with a crafted mimeTeX expression and cause
a denial of service or possibly execute arbitrary code. (CVE-2009-1382)

Chris Evans discovered that mimeTeX contained certain directives that may
be unsuitable for handling untrusted user input. This update fixed the
issue by disabling the \\input and \\counter tags. (CVE-2009-2459)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mimetex-1.50-1ubuntu0.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1382","CVE-2009-2459");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "mimetex", pkgver: "1.50-1ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mimetex-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mimetex-1.50-1ubuntu0.9.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
