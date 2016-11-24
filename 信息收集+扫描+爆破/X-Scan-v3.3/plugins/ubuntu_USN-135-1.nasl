# This script was automatically generated from the 135-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20526);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "135-1");
script_summary(english:"gdb vulnerabilities");
script_name(english:"USN135-1 : gdb vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gdb" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy found an integer overflow in the GNU debugger. By
tricking an user into merely load a specially crafted executable, an
attacker could exploit this to execute arbitrary code with the
privileges of the user running gdb. However, loading untrusted
binaries without actually executing them is rather uncommon, so the
risk of this flaw is low. (CVE-2005-1704)

Tavis Ormandy also discovered that gdb loads and executes the file
".gdbinit" in the current directory even if the file belongs to a
different user. By tricking an user into run gdb in a directory with a
malicious .gdbinit file, a local attacker could exploit this to run
arbitrary commands with the privileges of the user invoking gdb.
(CVE-2005-1705)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gdb-6.3-5ubuntu1.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2005-1704","CVE-2005-1705");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "gdb", pkgver: "6.3-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gdb-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gdb-6.3-5ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
