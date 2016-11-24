# This script was automatically generated from the SSA-2009-231-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40623);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2009-231-01 security update');
script_set_attribute(attribute:'description', value: '
This is a followup to the SSA:2009-230-01 advisory noting some errata.

The generic SMP kernel update for Slackware 12.2 was built using the
.config for a huge kernel, not a generic one.  The kernel previously
published as kernel-generic-smp and in the gemsmp.s directory works
and is secure, but is larger than it needs to be.  It has been
replaced in the Slackware 12.2 patches with a generic SMP kernel.

A new svgalib_helper package (compiled for a 2.6.27.31 kernel) was
added to the Slackware 12.2 /patches.

An error was noticed in the SSA:2009-230-01 advisory concerning the
packages for Slackware -current 32-bit.  The http links given refer to
packages with a -1 build version.  The actual packages have a build
number of -2.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2009-231-01");
script_summary("SSA-2009-231-01 kernel [updated] ");
script_name(english: "SSA-2009-231-01 kernel [updated] ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "12.2", pkgname: "kernel-modules-smp", pkgver: "2.6.27.31_smp", pkgnum:  "2", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-modules-smp is vulnerable in Slackware 12.2
Upgrade to kernel-modules-smp-2.6.27.31_smp-i686-2 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-generic-smp", pkgver: "2.6.27.31_smp", pkgnum:  "2", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-generic-smp is vulnerable in Slackware 12.2
Upgrade to kernel-generic-smp-2.6.27.31_smp-i686-2 or newer.
');
}
if (slackware_check(osver: "12.2", pkgname: "kernel-source", pkgver: "2.6.27.31_smp", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 12.2
Upgrade to kernel-source-2.6.27.31_smp-noarch-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
