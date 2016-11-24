# This script was automatically generated from the SSA-2008-042-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31027);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2008-042-01 security update');
script_set_attribute(attribute:'description', value: '
New kernel packages are available for Slackware 12.0, and -current to
fix a local root exploit.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0010
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0163
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0600


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2008-042-01");
script_summary("SSA-2008-042-01 kernel exploit fix ");
script_name(english: "SSA-2008-042-01 kernel exploit fix ");
script_cve_id("CVE-2008-0010","CVE-2008-0163","CVE-2008-0600");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "12.0", pkgname: "kernel-generic", pkgver: "2.6.21.5", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic is vulnerable in Slackware 12.0
Upgrade to kernel-generic-2.6.21.5-i486-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "kernel-generic-smp", pkgver: "2.6.21.5_smp", pkgnum:  "2", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic-smp is vulnerable in Slackware 12.0
Upgrade to kernel-generic-smp-2.6.21.5_smp-i686-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "kernel-huge", pkgver: "2.6.21.5", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-huge is vulnerable in Slackware 12.0
Upgrade to kernel-huge-2.6.21.5-i486-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "kernel-huge-smp", pkgver: "2.6.21.5_smp", pkgnum:  "2", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-huge-smp is vulnerable in Slackware 12.0
Upgrade to kernel-huge-smp-2.6.21.5_smp-i686-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-generic", pkgver: "2.6.23.16", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic is vulnerable in Slackware -current
Upgrade to kernel-generic-2.6.23.16-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-generic-smp", pkgver: "2.6.23.16_smp", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic-smp is vulnerable in Slackware -current
Upgrade to kernel-generic-smp-2.6.23.16_smp-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-huge", pkgver: "2.6.23.16", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-huge is vulnerable in Slackware -current
Upgrade to kernel-huge-2.6.23.16-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-huge-smp", pkgver: "2.6.23.16_smp", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-huge-smp is vulnerable in Slackware -current
Upgrade to kernel-huge-smp-2.6.23.16_smp-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules", pkgver: "2.6.23.16", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules is vulnerable in Slackware -current
Upgrade to kernel-modules-2.6.23.16-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules-smp", pkgver: "2.6.23.16_smp", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules-smp is vulnerable in Slackware -current
Upgrade to kernel-modules-smp-2.6.23.16_smp-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.6.23.16_smp", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.6.23.16_smp-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.6.23.16_smp", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.6.23.16_smp-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
