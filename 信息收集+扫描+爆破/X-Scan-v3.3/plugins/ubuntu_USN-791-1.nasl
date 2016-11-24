# This script was automatically generated from the 791-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39516);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "791-1");
script_summary(english:"moodle vulnerabilities");
script_name(english:"USN791-1 : moodle vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "moodle" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Thor Larholm discovered that PHPMailer, as used by Moodle, did not
correctly escape email addresses.  A local attacker with direct access
to the Moodle database could exploit this to execute arbitrary commands
as the web server user. (CVE-2007-3215)

Nigel McNie discovered that fetching https URLs did not correctly escape
shell meta-characters.  An authenticated remote attacker could execute
arbitrary commands as the web server user, if curl was installed and
configured. (CVE-2008-4796, MSA-09-0003)

It was discovered that Smarty (also included in Moodle), did not
correctly filter certain inputs.  An authenticated remote attacker could
exploit this to execute arbitrary PHP commands as the web server user.
(CVE-2008-4810, CVE-2008-4811, CVE-2009-1669)

It was discovered that the unused SpellChecker extension in Moodle did not
correctly handle temporary files.  If the tool had been locally modified,
it could be made to overwrite arbitrary local files via symlinks.
(CVE-2008-5153)

Mike Churchward discovered th
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- moodle-1.8.2-1.2ubuntu2.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3215","CVE-2008-4796","CVE-2008-4810","CVE-2008-4811","CVE-2008-5153","CVE-2008-5432","CVE-2008-5619","CVE-2008-6124","CVE-2009-0499","CVE-2009-0500","CVE-2009-0501","CVE-2009-0502","CVE-2009-1171","CVE-2009-1669");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "moodle", pkgver: "1.8.2-1.2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moodle-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to moodle-1.8.2-1.2ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
