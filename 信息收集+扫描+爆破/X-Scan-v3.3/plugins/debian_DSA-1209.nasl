# This script was automatically generated from the dsa-1209
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23658);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1209");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1209 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that Trac, a wiki and issue tracking system for
software development projects, performs insufficient validation against
cross-site request forgery, which might lead to an attacker being able
to perform manipulation of a Trac site with the privileges of the
attacked Trac user.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1-3sarge7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1209');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your trac package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1209] DSA-1209-2 trac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1209-2 trac");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
