# This script was automatically generated from the SSA-2004-299-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18793);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-299-01 security update');
script_set_attribute(attribute:'description', value: '
New apache and mod_ssl packages are available for Slackware 8.1, 9.0, 9.1,
10.0, and -current to fix security issues.  Apache has been upgraded to
version 1.3.32 which fixes a heap-based buffer overflow in mod_proxy.
mod_ssl was upgraded from version mod_ssl-2.8.19-1.3.31 to version
2.8.21-1.3.32 which corrects a flaw allowing a client to use a cipher
which the server does not consider secure enough.

A new PHP package (php-4.3.9) is also available for all of these platforms.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0492
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0885


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-299-01");
script_summary("SSA-2004-299-01 apache, mod_ssl, php  ");
script_name(english: "SSA-2004-299-01 apache, mod_ssl, php  ");
script_cve_id("CVE-2004-0492","CVE-2004-0885");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.32", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.32-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "mod_ssl", pkgver: "2.8.21_1.3.32", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mod_ssl is vulnerable in Slackware 8.1
Upgrade to mod_ssl-2.8.21_1.3.32-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.3.9", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.3.9-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "apache", pkgver: "1.3.32", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 9.0
Upgrade to apache-1.3.32-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "mod_ssl", pkgver: "2.8.21_1.3.32", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mod_ssl is vulnerable in Slackware 9.0
Upgrade to mod_ssl-2.8.21_1.3.32-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "php", pkgver: "4.3.9", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 9.0
Upgrade to php-4.3.9-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "apache", pkgver: "1.3.32", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 9.1
Upgrade to apache-1.3.32-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mod_ssl", pkgver: "2.8.21_1.3.32", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mod_ssl is vulnerable in Slackware 9.1
Upgrade to mod_ssl-2.8.21_1.3.32-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "php", pkgver: "4.3.9", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 9.1
Upgrade to php-4.3.9-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "apache", pkgver: "1.3.32", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 10.0
Upgrade to apache-1.3.32-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mod_ssl", pkgver: "2.8.21_1.3.32", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mod_ssl is vulnerable in Slackware 10.0
Upgrade to mod_ssl-2.8.21_1.3.32-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "php", pkgver: "4.3.9", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 10.0
Upgrade to php-4.3.9-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.32", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.32-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mod_ssl", pkgver: "2.8.21_1.3.32", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mod_ssl is vulnerable in Slackware -current
Upgrade to mod_ssl-2.8.21_1.3.32-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.3.9", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.3.9-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
