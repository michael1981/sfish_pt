# This script was automatically generated from the 520-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28125);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "520-1");
script_summary(english:"fetchmail vulnerabilities");
script_name(english:"USN520-1 : fetchmail vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- fetchmail 
- fetchmailconf 
');
script_set_attribute(attribute:'description', value: 'Gaetan Leurent discovered a vulnerability in the APOP protocol based
on MD5 collisions. As fetchmail supports the APOP protocol, this
vulnerability can be used by attackers to discover a portion of the APOP
user\'s authentication credentials. (CVE-2007-1558)

Earl Chew discovered that fetchmail can be made to de-reference a NULL
pointer when contacting SMTP servers. This vulnerability can be used
by attackers who control the SMTP server to crash fetchmail and cause
a denial of service. (CVE-2007-4565)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- fetchmail-6.3.6-1ubuntu2.1 (Ubuntu 7.04)
- fetchmailconf-6.3.6-1ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1558","CVE-2007-4565");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "fetchmail", pkgver: "6.3.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmail-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to fetchmail-6.3.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "fetchmailconf", pkgver: "6.3.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmailconf-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to fetchmailconf-6.3.6-1ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
