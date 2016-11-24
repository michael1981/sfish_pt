# This script was automatically generated from the SSA-2005-310-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20150);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2005-310-02 security update');
script_set_attribute(attribute:'description', value: '
New KOffice packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 
and -current to fix a security issue with KWord.  A buffer overflow in
the RTF import functionality could result in the execution of arbitrary
code.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2971


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2005-310-02");
script_summary("SSA-2005-310-02 KOffice/KWord ");
script_name(english: "SSA-2005-310-02 KOffice/KWord ");
script_cve_id("CVE-2005-2971");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "koffice", pkgver: "1.2.1", pkgnum:  "6", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware 9.1
Upgrade to koffice-1.2.1-i486-6 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "koffice", pkgver: "1.3.1", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware 10.0
Upgrade to koffice-1.3.1-i486-4 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "koffice", pkgver: "1.3.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware 10.1
Upgrade to koffice-1.3.5-i486-3 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "koffice", pkgver: "1.4.1", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware 10.2
Upgrade to koffice-1.4.1-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "koffice", pkgver: "1.4.1", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware -current
Upgrade to koffice-1.4.1-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
