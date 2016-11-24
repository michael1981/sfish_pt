# This script was automatically generated from the SSA-2009-230-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40622);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2009-230-01 security update');
script_set_attribute(attribute:'description', value: '
New Linux kernel packages are available for Slackware 12.2 and -current
to address a security issue.  A kernel bug discovered by Tavis Ormandy
and Julien Tinnes of the Google Security Team could allow a local user 
to fill memory page zero with arbitrary code and then use the kernel
sendpage operation to trigger a NULL pointer dereference, executing the
code in the context of the kernel.  If successfully exploited, this bug
can be used to gain root access.

At this time we have prepared fixed kernels for the stable version of
Slackware (12.2), as well as for both 32-bit x86 and x86_64 -current
versions.  Additionally, we have added a package to the /patches
directory for Slackware 12.1 and 12.2 that will set the minimum memory
page that can be mmap()ed from userspace without additional privileges
to 4096.  The package will work with any kernel supporting the
vm.mmap_min_addr tunable, and should significantly reduce the potential
harm from this bug, as well as future similar bugs that might be found
in the kernel.  More updated kernels may follow.

For more information, see:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2692


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2009-230-01");
script_summary("SSA-2009-230-01 kernel ");
script_name(english: "SSA-2009-230-01 kernel ");
script_cve_id("CVE-2009-2692");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "12.2", pkgname: "kernel-firmware", pkgver: "2.6.27.31", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-firmware is vulnerable in Slackware 12.2
Upgrade to kernel-firmware-2.6.27.31-noarch-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-generic", pkgver: "2.6.27.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic is vulnerable in Slackware 12.2
Upgrade to kernel-generic-2.6.27.31-i486-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-generic-smp", pkgver: "2.6.27.31_smp", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic-smp is vulnerable in Slackware 12.2
Upgrade to kernel-generic-smp-2.6.27.31_smp-i686-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-huge", pkgver: "2.6.27.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-huge is vulnerable in Slackware 12.2
Upgrade to kernel-huge-2.6.27.31-i486-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-huge-smp", pkgver: "2.6.27.31_smp", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-huge-smp is vulnerable in Slackware 12.2
Upgrade to kernel-huge-smp-2.6.27.31_smp-i686-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-modules", pkgver: "2.6.27.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules is vulnerable in Slackware 12.2
Upgrade to kernel-modules-2.6.27.31-i486-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-modules-smp", pkgver: "2.6.27.31_smp", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules-smp is vulnerable in Slackware 12.2
Upgrade to kernel-modules-smp-2.6.27.31_smp-i686-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-source", pkgver: "2.6.27.31_smp", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 12.2
Upgrade to kernel-source-2.6.27.31_smp-noarch-1 or newer.
');
}
if (slackware_check(osver: "12.1", pkgname: "kernel-mmap_min_addr", pkgver: "4096", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-mmap_min_addr is vulnerable in Slackware 12.1
Upgrade to kernel-mmap_min_addr-4096-noarch-1 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-mmap_min_addr", pkgver: "4096", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-mmap_min_addr is vulnerable in Slackware 12.2
Upgrade to kernel-mmap_min_addr-4096-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
