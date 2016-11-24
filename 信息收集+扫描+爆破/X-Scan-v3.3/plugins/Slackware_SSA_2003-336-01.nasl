# This script was automatically generated from the SSA-2003-336-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18743);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2003-336-01 security update');
script_set_attribute(attribute:'description', value: '
New kernels are available for Slackware 9.1 and -current.  These
have been upgraded to Linux kernel version 2.4.23, which fixes a
bug in the kernel\'s do_brk() function that could be exploited to
gain root privileges.  These updated kernels and modules should be
installed by any sites running a 2.4 kernel earlier than 2.4.23.
Linux 2.0 and 2.2 kernels are not vulnerable.

More details about the Apache issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0961


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2003-336-01");
script_summary("SSA-2003-336-01 Kernel security update  ");
script_name(english: "SSA-2003-336-01 Kernel security update  ");
script_cve_id("CVE-2003-0961");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules is vulnerable in Slackware 9.1
Upgrade to kernel-modules-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.23", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.23-noarch-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-driver is vulnerable in Slackware 9.1
Upgrade to alsa-driver-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-lib", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-lib is vulnerable in Slackware 9.1
Upgrade to alsa-lib-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-oss", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-oss is vulnerable in Slackware 9.1
Upgrade to alsa-oss-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-utils", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-utils is vulnerable in Slackware 9.1
Upgrade to alsa-utils-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-driver-xfs", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-driver-xfs is vulnerable in Slackware 9.1
Upgrade to alsa-driver-xfs-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules-xfs", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules-xfs is vulnerable in Slackware 9.1
Upgrade to kernel-modules-xfs-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules is vulnerable in Slackware -current
Upgrade to kernel-modules-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.23-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.23", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.23-noarch-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-utils", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-utils is vulnerable in Slackware -current
Upgrade to alsa-utils-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-driver is vulnerable in Slackware -current
Upgrade to alsa-driver-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-lib", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-lib is vulnerable in Slackware -current
Upgrade to alsa-lib-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-oss", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-oss is vulnerable in Slackware -current
Upgrade to alsa-oss-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver-xfs", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package alsa-driver-xfs is vulnerable in Slackware -current
Upgrade to alsa-driver-xfs-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules-xfs", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules-xfs is vulnerable in Slackware -current
Upgrade to kernel-modules-xfs-2.4.23-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
