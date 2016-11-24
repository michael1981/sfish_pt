# This script was automatically generated from the 390-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27975);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "390-3");
script_summary(english:"evince-gtk vulnerability");
script_name(english:"USN390-3 : evince-gtk vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "evince-gtk" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-390-2 fixed vulnerabilities in evince.  This update provides the 
corresponding update for evince-gtk.

Original advisory details:

  A buffer overflow was discovered in the PostScript processor included 
  in evince.  By tricking a user into opening a specially crafted PS 
  file, an attacker could crash evince or execute arbitrary code with 
  the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- evince-gtk-0.5.2-0ubuntu4.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5864");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "evince-gtk", pkgver: "0.5.2-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evince-gtk-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to evince-gtk-0.5.2-0ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
