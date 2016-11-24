# This script was automatically generated from the SSA-2006-200-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(22081);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-200-01 security update');
script_set_attribute(attribute:'description', value: '
New Samba packages are available for Slackware 10.0, 10.1, 10.2,
and -current.

In Slackware 10.0, 10.1, and 10.2, Samba was evidently picking up
the libdm.so.0 library causing a Samba package issued primarily as
a security patch to suddenly require a library that would only be
present on the machine if the xfsprogs package (from the A series
but marked "optional") was installed.  Sorry -- this was not
intentional, though I do know that I\'m taking the chance of this
kind of issue when trying to get security related problems fixed
quickly (hopefully balanced with reasonable testing), and when the
fix is achieved by upgrading to a new version rather than with the
smallest patch possible to fix the known issue.  However, I tend
to trust that by following upstream sources as much as possible
I\'m also fixing some problems that aren\'t yet public.

So, all of the the 10.0, 10.1, and 10.2 packages have been rebuilt
on systems without the dm library, and should be able to directly
upgrade older samba packages without additional requirements.
Well, unless they are also under /patches.  ;-)

All the packages (including -current) have been patched with a
fix from Samba\'s CVS for some reported problems with winbind.
Thanks to Mikhail Kshevetskiy for pointing me to the patch.

I realize these packages don\'t really fix security issues, but
they do fix security patch packages that are less than a couple
of days old, so it seems prudent to notify slackware-security
(and any subscribed lists) again.  Sorry if it\'s noise...


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-200-01");
script_summary("SSA-2006-200-01 Samba 2.0.23 repackaged ");
script_name(english: "SSA-2006-200-01 Samba 2.0.23 repackaged ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.0", pkgname: "samba", pkgver: "3.0.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package samba is vulnerable in Slackware 10.0
Upgrade to samba-3.0.23-i486-2_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "samba", pkgver: "3.0.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package samba is vulnerable in Slackware 10.1
Upgrade to samba-3.0.23-i486-2_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "samba", pkgver: "3.0.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package samba is vulnerable in Slackware 10.2
Upgrade to samba-3.0.23-i486-2_slack10.2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "samba", pkgver: "3.0.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package samba is vulnerable in Slackware -current
Upgrade to samba-3.0.23-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
