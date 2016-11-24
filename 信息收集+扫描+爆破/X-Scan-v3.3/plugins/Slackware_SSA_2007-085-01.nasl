# This script was automatically generated from the SSA-2007-085-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(24914);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-085-01 security update');
script_set_attribute(attribute:'description', value: '
New mozilla-firefox packages are available for Slackware 10.2, 11.0,
and -current to fix security issues.

Note that firefox-1.5.x will reach end-of-life next month, so upgrading
to the 2.x branch soon is probably a good idea.

- From http://developer.mozilla.org/devnews/index.php/2007/03/
  "Note: Firefox 1.5.0.x will be maintained with security and stability
   updates until April 24, 2007. All users are encouraged to upgrade
   to Firefox 2."

Since Slackware packages the official Firefox binaries, the Firefox 2
packages in Slackware 11.0 and -current should run on many earlier
Slackware versions as well, though there are some known problems with
plugins (such as gxine).


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-085-01");
script_summary("SSA-2007-085-01 mozilla-firefox ");
script_name(english: "SSA-2007-085-01 mozilla-firefox ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.2", pkgname: "mozilla-firefox", pkgver: "1.5.0.11", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-firefox is vulnerable in Slackware 10.2
Upgrade to mozilla-firefox-1.5.0.11-i686-1 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "mozilla-firefox", pkgver: "1.5.0.11", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-firefox is vulnerable in Slackware 11.0
Upgrade to mozilla-firefox-1.5.0.11-i686-1 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "mozilla-firefox", pkgver: "2.0.0.3", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-firefox is vulnerable in Slackware 11.0
Upgrade to mozilla-firefox-2.0.0.3-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla-firefox", pkgver: "2.0.0.3", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-firefox is vulnerable in Slackware -current
Upgrade to mozilla-firefox-2.0.0.3-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
