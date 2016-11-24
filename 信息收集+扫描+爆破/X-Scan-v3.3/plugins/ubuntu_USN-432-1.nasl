# This script was automatically generated from the 432-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28026);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "432-1");
script_summary(english:"GnuPG vulnerability");
script_name(english:"USN432-1 : GnuPG vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gnupg" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Gerardo Richarte from Core Security Technologies discovered that when 
gnupg is used without --status-fd, there is no way to distinguish 
initial unsigned messages from a following signed message.  An attacker 
could inject an unsigned message, which could fool the user into 
thinking the message was entirely signed by the original sender.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnupg-1.4.3-2ubuntu3.3 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-1263");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "gnupg", pkgver: "1.4.3-2ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnupg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to gnupg-1.4.3-2ubuntu3.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
