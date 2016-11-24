# This script was automatically generated from the dsa-1753
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36046);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1753");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1753 security update');
 script_set_attribute(attribute: 'description', value:
'As indicated in the Etch release notes, security support for the
Iceweasel version in the oldstable distribution (Etch) needed to be
stopped before the end of the regular security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.
On a side note, please note that the Debian stable/Lenny version of
Iceweasel - the unbranded version of the Firefox browser - links
dynamically against the Xulrunner library. As such, most of the
vulnerabilities found in Firefox need only be fixed in the Xulrunner
package and don\'t require updates to the Iceweasel package any longer.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1753');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2009/dsa-1753
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1753] DSA-1753-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1753-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
