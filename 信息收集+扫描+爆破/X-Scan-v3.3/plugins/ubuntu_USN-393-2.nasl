# This script was automatically generated from the 393-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27979);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "393-2");
script_summary(english:"GnuPG2 vulnerabilities");
script_name(english:"USN393-2 : GnuPG2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gnupg-agent 
- gnupg2 
- gpgsm 
');
script_set_attribute(attribute:'description', value: 'USN-389-1 and USN-393-1 fixed vulnerabilities in gnupg.  This update 
provides the corresponding updates for gnupg2.

Original advisory details:

  A buffer overflow was discovered in GnuPG.  By tricking a user into 
  running gpg interactively on a specially crafted message, an attacker 
  could execute arbitrary code with the user\'s privileges.  This 
  vulnerability is not exposed when running gpg in batch mode.  
  (CVE-2006-6169)

  Tavis Ormandy discovered that gnupg was incorrectly using the stack.  
  If a user were tricked into processing a specially crafted message, an 
  attacker could execute arbitrary code with the user\'s privileges.
  (CVE-2006-6235)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnupg-agent-1.9.21-0ubuntu5.2 (Ubuntu 6.10)
- gnupg2-1.9.21-0ubuntu5.2 (Ubuntu 6.10)
- gpgsm-1.9.21-0ubuntu5.2 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-6169","CVE-2006-6235");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "gnupg-agent", pkgver: "1.9.21-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnupg-agent-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to gnupg-agent-1.9.21-0ubuntu5.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "gnupg2", pkgver: "1.9.21-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnupg2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to gnupg2-1.9.21-0ubuntu5.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "gpgsm", pkgver: "1.9.21-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gpgsm-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to gpgsm-1.9.21-0ubuntu5.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
