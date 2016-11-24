# This script was automatically generated from the SSA-2004-119-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18792);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-119-01 security update');
script_set_attribute(attribute:'description', value: '
New kernel packages are available for Slackware 9.1 and -current to
fix security issues.  Also available are new kernel modules packages
(including alsa-driver), and a new version of the hotplug package
for Slackware 9.1 containing some fixes for using 2.4.26 (and 2.6.x)
kernel modules.

The most serious of the fixed issues is an overflow in ip_setsockopt(),
which could allow a local attacker to gain root access, or to crash or
reboot the machine.  This bug affects 2.4 kernels from 2.4.22 - 2.4.25.
Any sites running one of those kernel versions should upgrade right
away.  After installing the new kernel, be sure to run \'lilo\'.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0394
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0424


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-119-01");
script_summary("SSA-2004-119-01 kernel security updates ");
script_name(english: "SSA-2004-119-01 kernel security updates ");
script_cve_id("CVE-2004-0394","CVE-2004-0424");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-driver is vulnerable in Slackware 9.1
Upgrade to alsa-driver-0.9.8-i486-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "hotplug", pkgver: "2004_01_05", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package hotplug is vulnerable in Slackware 9.1
Upgrade to hotplug-2004_01_05-noarch-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.26-i486-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-headers", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-headers is vulnerable in Slackware 9.1
Upgrade to kernel-headers-2.4.26-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules is vulnerable in Slackware 9.1
Upgrade to kernel-modules-2.4.26-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.26-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.26-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules is vulnerable in Slackware -current
Upgrade to kernel-modules-2.4.26-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.26-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.26-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver", pkgver: "1.0.4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-driver is vulnerable in Slackware -current
Upgrade to alsa-driver-1.0.4-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
