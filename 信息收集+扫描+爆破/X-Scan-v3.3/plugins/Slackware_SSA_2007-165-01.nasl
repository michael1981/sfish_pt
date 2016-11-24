# This script was automatically generated from the SSA-2007-165-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(25772);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-165-01 security update');
script_set_attribute(attribute:'description', value: '
A new thunderbird package is available for Slackware -current to
fix two possible security issues.  This package may also be used on
many older versions of Slackware (though we\'re not certain how far
back...)

More details about the issues may be found here:
  http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird


Here are the details from the Slackware -current ChangeLog:
+--------------------------+
xap/mozilla-thunderbird-2.0.0.4-i686-1.tgz:  Upgraded to thunderbird-2.0.0.4.
  This upgrade fixes two possible security bugs.
  For more information, see:
    http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird
  (* Security fix *)
+--------------------------+

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-165-01");
script_summary("SSA-2007-165-01 thunderbird ");
script_name(english: "SSA-2007-165-01 thunderbird ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "-current", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.4", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-thunderbird is vulnerable in Slackware -current
Upgrade to mozilla-thunderbird-2.0.0.4-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
