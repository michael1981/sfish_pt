# This script was automatically generated from the SSA-2006-045-08
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20919);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-045-08 security update');
script_set_attribute(attribute:'description', value: '[slackware-security]  Mutt buffer overflow in IMAP support

The mutt mail client packages in Slackware 8.1 and 9.0 have been
upgraded to mutt-1.4.1i to fix a security problem discovered by
Core Security Technologies.  This issue may allow a remote
attacker controlling a malicious IMAP server to execute code on
your machine as the user running mutt if you connect to the IMAP
server using mutt.

All sites running mutt are advised to upgrade.  

More information on the problem can be found here:

http://www.coresecurity.com/common/showdoc.php?idx=310&amp;idxseccion=10

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-045-08");
script_summary("SSA-2006-045-08 Mutt buffer overflow in IMAP support");
script_name(english: "SSA-2006-045-08 Mutt buffer overflow in IMAP support");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "mutt", pkgver: "1.4.1i", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mutt is vulnerable in Slackware 8.1
Upgrade to mutt-1.4.1i-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "mutt", pkgver: "1.4.1i", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mutt is vulnerable in Slackware 9.0
Upgrade to mutt-1.4.1i-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
