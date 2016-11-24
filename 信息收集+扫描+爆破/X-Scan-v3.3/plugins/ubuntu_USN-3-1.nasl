# This script was automatically generated from the 3-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20645);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "3-1");
script_summary(english:"GhostScript utility script vulnerabilities");
script_name(english:"USN3-1 : GhostScript utility script vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gs-common" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Recently, Trustix Secure Linux discovered some vulnerabilities in the
gs-common package. The utilities "pv.sh" and "ps2epsi" created
temporary files in an insecure way, which allowed a symlink attack to
create or overwrite arbitrary files with the privileges of the user
invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gs-common-0.3.6ubuntu1.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2004-0967");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "gs-common", pkgver: "0.3.6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gs-common-0.3.6ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
