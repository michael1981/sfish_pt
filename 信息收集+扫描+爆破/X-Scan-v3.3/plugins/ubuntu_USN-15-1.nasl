# This script was automatically generated from the 15-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20547);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "15-1");
script_summary(english:"lvm10 vulnerability");
script_name(english:"USN15-1 : lvm10 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "lvm10" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Recently, Trustix Secure Linux discovered a vulnerability in a
supplemental script of the lvm10 package. The program
"lvmcreate_initrd" created a temporary directory in an insecure way,
which could allow a symlink attack to create or overwrite arbitrary
files with the privileges of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- lvm10-1.0.8-4ubuntu1.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2004-0972");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "lvm10", pkgver: "1.0.8-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lvm10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lvm10-1.0.8-4ubuntu1.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
