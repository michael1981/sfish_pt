# This script was automatically generated from the dsa-088
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14925);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "088");
 script_bugtraq_id(3623);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-088 security update');
 script_set_attribute(attribute: 'description', value:
'The fml (a mailing list package) as distributed in Debian GNU/Linux 2.2
suffers from a cross-site scripting problem. When generating index
pages for list archives the `<\' and `>\' characters were not properly
escaped for subjects.

This has been fixed in version 3.0+beta.20000106-5, and we recommend
that you upgrade your fml package to that version. Upgrading will
automatically regenerate the index pages.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-088');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-088
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA088] DSA-088-1 fml");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-088-1 fml");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fml', release: '2.2', reference: '3.0+beta.20000106-5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
