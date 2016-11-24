# This script was automatically generated from the 658-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36491);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "658-1");
script_summary(english:"moodle vulnerability");
script_name(english:"USN658-1 : moodle vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "moodle" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Lukasz Pilorz discovered that the HTML filtering used in Moodle was not
strict enough.  A remote attacker could send malicious requests to Moodle
and execute arbitrary code as the web server user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- moodle-1.8.2-1ubuntu4.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-1502");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "moodle", pkgver: "1.8.2-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moodle-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to moodle-1.8.2-1ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
