# This script was automatically generated from the 500-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28103);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "500-1");
script_summary(english:"rsync vulnerability");
script_name(english:"USN500-1 : rsync vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "rsync" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Sebastian Krahmer discovered that rsync contained an off-by-one
miscalculation when handling certain file paths.  By creating a specially
crafted tree of files and tricking an rsync server into processing them,
a remote attacker could write a single NULL to stack memory, possibly
leading to arbitrary code execution.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- rsync-2.6.9-3ubuntu1.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4091");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "rsync", pkgver: "2.6.9-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rsync-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to rsync-2.6.9-3ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
