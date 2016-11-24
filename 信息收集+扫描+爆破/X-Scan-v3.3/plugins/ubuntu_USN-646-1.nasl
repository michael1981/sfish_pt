# This script was automatically generated from the 646-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38000);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "646-1");
script_summary(english:"rdesktop vulnerabilities");
script_name(english:"USN646-1 : rdesktop vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "rdesktop" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that rdesktop did not properly validate the length
of packet headers when processing RDP requests. If a user were tricked
into connecting to a malicious server, an attacker could cause a
denial of service or possible execute arbitrary code with the
privileges of the user. (CVE-2008-1801)

Multiple buffer overflows were discovered in rdesktop when processing
RDP redirect requests. If a user were tricked into connecting to a
malicious server, an attacker could cause a denial of service or
possible execute arbitrary code with the privileges of the user.
(CVE-2008-1802)

It was discovered that rdesktop performed a signed integer comparison
when reallocating dynamic buffers which could result in a heap-based
overflow. If a user were tricked into connecting to a malicious
server, an attacker could cause a denial of service or possible
execute arbitrary code with the privileges of the user.
(CVE-2008-1802)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- rdesktop-1.5.0-3+cvs20071006ubuntu0.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1801","CVE-2008-1802","CVE-2008-1803");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "rdesktop", pkgver: "1.5.0-3+cvs20071006ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdesktop-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to rdesktop-1.5.0-3+cvs20071006ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
