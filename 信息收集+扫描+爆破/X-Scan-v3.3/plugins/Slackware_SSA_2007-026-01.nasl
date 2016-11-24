# This script was automatically generated from the SSA-2007-026-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(24667);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-026-01 security update');
script_set_attribute(attribute:'description', value: 'An exploitable overflow has been found in the address handling code of the
mutt mail client version 1.2.5i supplied with Slackware 8.0.  A new
mutt-1.2.5.1 has been released which addresses this problem, and packages
are now available for Slackware 8.0 and -current.

We urge all Slackware users to upgrade to this new version of mutt as soon
as possible.

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-026-01");
script_summary("SSA-2007-026-01 mutt remote exploit patched");
script_name(english: "SSA-2007-026-01 mutt remote exploit patched");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "-current", pkgname: "mutt", pkgver: "1.2.5.1", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mutt is vulnerable in Slackware -current
Upgrade to mutt-1.2.5.1-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
