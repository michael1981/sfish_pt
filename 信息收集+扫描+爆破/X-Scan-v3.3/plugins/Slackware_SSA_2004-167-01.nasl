# This script was automatically generated from the SSA-2004-167-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18791);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-167-01 security update');
script_set_attribute(attribute:'description', value: '
New kernel packages are available for Slackware 8.1, 9.0, 9.1,
and -current to fix a denial of service security issue.  Without
a patch to asm-i386/i387.h, a local user can crash the machine.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0554

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-167-01");
script_summary("SSA-2004-167-01 kernel DoS ");
script_name(english: "SSA-2004-167-01 kernel DoS ");
script_cve_id("CVE-2004-0554");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "kernel-ide", pkgver: "2.4.18", pkgnum:  "6", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware 8.1
Upgrade to kernel-ide-2.4.18-i386-6 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "kernel-source", pkgver: "2.4.18", pkgnum:  "7", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 8.1
Upgrade to kernel-source-2.4.18-noarch-7 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-ide", pkgver: "2.4.21", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware 9.0
Upgrade to kernel-ide-2.4.21-i486-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-source", pkgver: "2.4.21", pkgnum:  "4", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 9.0
Upgrade to kernel-source-2.4.21-noarch-4 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.26-i486-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.26-noarch-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.26-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.26", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.26-i386-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "4", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.26-noarch-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-generic", pkgver: "2.6.6", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic is vulnerable in Slackware -current
Upgrade to kernel-generic-2.6.6-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.6.6", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.6.6-i386-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.6.6", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.6.6-noarch-3 or newer.
');
}

if (w) { security_note(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
