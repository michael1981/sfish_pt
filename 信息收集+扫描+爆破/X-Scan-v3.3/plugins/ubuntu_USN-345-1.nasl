# This script was automatically generated from the 345-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27924);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "345-1");
script_summary(english:"mailman vulnerabilities");
script_name(english:"USN345-1 : mailman vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mailman" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Steve Alexander discovered that mailman did not properly handle
attachments with special filenames. A remote user could exploit that
to stop mail delivery until the server administrator manually cleaned
these posts. (CVE-2006-2941)

Various cross-site scripting vulnerabilities have been reported by
Barry Warsaw. By using specially crafted email addresses, names, and
similar arbitrary user-defined strings, a remote attacker could
exploit this to run web script code in the list administrator\'s
web browser. (CVE-2006-3636)

URLs logged to the error log file are now checked for invalid
characters. Before, specially crafted URLs could inject arbitrary
messages into the log.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mailman-2.1.5-9ubuntu4.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2941","CVE-2006-3636");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "mailman", pkgver: "2.1.5-9ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mailman-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mailman-2.1.5-9ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
