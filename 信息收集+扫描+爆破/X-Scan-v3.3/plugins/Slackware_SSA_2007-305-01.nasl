# This script was automatically generated from the SSA-2007-305-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27609);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-305-01 security update');
script_set_attribute(attribute:'description', value: '
CUPS was found to contain errors in ipp.c which could allow a remote attacker
to crash CUPS, resulting in a denial of service.  If you use CUPS, it is
recommended to update to the latest package for your version of Slackware.

The latest cups package is available for Slackware -current, and patched
packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1, 10.2, 11.0, 
and 12.0 that fix the problems.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4351


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-305-01");
script_summary("SSA-2007-305-01 cups ");
script_name(english: "SSA-2007-305-01 cups ");
script_cve_id("CVE-2007-4351");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "cups", pkgver: "1.1.19", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 8.1
Upgrade to cups-1.1.19-i386-2_slack8.1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "cups", pkgver: "1.1.19", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 9.0
Upgrade to cups-1.1.19-i386-2_slack9.0 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "cups", pkgver: "1.1.21", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 9.1
Upgrade to cups-1.1.21-i486-2_slack9.1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "cups", pkgver: "1.1.21", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 10.0
Upgrade to cups-1.1.21-i486-2_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "cups", pkgver: "1.1.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 10.1
Upgrade to cups-1.1.23-i486-2_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "cups", pkgver: "1.1.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 10.2
Upgrade to cups-1.1.23-i486-2_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "cups", pkgver: "1.1.23", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 11.0
Upgrade to cups-1.1.23-i486-5_slack11.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "cups", pkgver: "1.2.11", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware 12.0
Upgrade to cups-1.2.11-i486-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "cups", pkgver: "1.3.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cups is vulnerable in Slackware -current
Upgrade to cups-1.3.3-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
