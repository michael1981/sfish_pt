# This script was automatically generated from the dsa-1754
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36134);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1754");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1754 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that roundup, an issue tracker with a command-line,
web and email interface, allows users to edit resources in
unauthorized ways, including granting themselves admin rights.
This update introduces stricter access checks, actually enforcing the
configured permissions and roles.  This means that the configuration
may need updating.  In addition, user registration via the web
interface has been disabled; use the program "roundup-admin" from the
command line instead.
For the old stable distribution (etch), this problem has been fixed in
version 1.2.1-10+etch1.
For the stable distribution (lenny), this problem has been fixed in
version 1.4.4-4+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1754');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your roundup package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1754] DSA-1754-1 roundup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1754-1 roundup");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'roundup', release: '4.0', reference: '1.2.1-10+etch1');
deb_check(prefix: 'roundup', release: '5.0', reference: '1.4.4-4+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
