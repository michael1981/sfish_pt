# This script was automatically generated from the 719-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36218);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "719-1");
script_summary(english:"libpam-krb5 vulnerabilities");
script_name(english:"USN719-1 : libpam-krb5 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "libpam-krb5" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that pam_krb5 parsed environment variables when run with
setuid applications. A local attacker could exploit this flaw to bypass
authentication checks and gain root privileges. (CVE-2009-0360)

Derek Chan discovered that pam_krb5 incorrectly handled refreshing existing
credentials when used with setuid applications. A local attacker could exploit
this to create or overwrite arbitrary files, and possibly gain root privileges.
(CVE-2009-0361)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-krb5-3.10-1ubuntu0.8.10.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0360","CVE-2009-0361");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libpam-krb5", pkgver: "3.10-1ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-krb5-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpam-krb5-3.10-1ubuntu0.8.10.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
