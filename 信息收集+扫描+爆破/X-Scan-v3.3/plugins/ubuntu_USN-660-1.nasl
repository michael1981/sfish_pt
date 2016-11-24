# This script was automatically generated from the 660-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38023);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "660-1");
script_summary(english:"enscript vulnerability");
script_name(english:"USN660-1 : enscript vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "enscript" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Ulf Härnhammar discovered multiple stack overflows in enscript\'s handling of
special escape arguments.  If a user or automated system were tricked into
processing a malicious file with the "-e" option enabled, a remote attacker
could execute arbitrary code or cause enscript to crash, possibly leading
to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- enscript-1.6.4-12ubuntu0.8.10.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-3863","CVE-2008-4306");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "enscript", pkgver: "1.6.4-12ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package enscript-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to enscript-1.6.4-12ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
