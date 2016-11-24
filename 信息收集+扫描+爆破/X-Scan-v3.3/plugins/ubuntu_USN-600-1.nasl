# This script was automatically generated from the 600-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31966);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "600-1");
script_summary(english:"rsync vulnerability");
script_name(english:"USN600-1 : rsync vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "rsync" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Sebastian Krahmer discovered that rsync could overflow when handling ACLs.
An attacker could construct a malicious set of files that when processed
by rsync could lead to arbitrary code execution or a crash.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- rsync-2.6.9-5ubuntu1.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1720");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "rsync", pkgver: "2.6.9-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rsync-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to rsync-2.6.9-5ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
