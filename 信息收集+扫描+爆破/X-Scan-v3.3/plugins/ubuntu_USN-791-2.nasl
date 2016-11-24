# This script was automatically generated from the 791-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39517);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "791-2");
script_summary(english:"moodle vulnerability");
script_name(english:"USN791-2 : moodle vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "moodle" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Christian Eibl discovered that the TeX filter in Moodle allowed any
function to be used.  An authenticated remote attacker could post
a specially crafted TeX formula to execute arbitrary TeX functions,
potentially reading any file accessible to the web server user, leading
to a loss of privacy.  (CVE-2009-1171, MSA-09-0009)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- moodle-1.9.4.dfsg-0ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2009-1171");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "moodle", pkgver: "1.9.4.dfsg-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moodle-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to moodle-1.9.4.dfsg-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
