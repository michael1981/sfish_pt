# This script was automatically generated from the dsa-1757
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36047);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1757");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1757 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that auth2db, an IDS logger, log viewer and alert
generator, is prone to an SQL injection vulnerability, when used with
multibyte character encodings.
The oldstable distribution (etch) doesn\'t contain auth2db.
For the stable distribution (lenny), this problem has been fixed in
version 0.2.5-2+dfsg-1+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1757');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your auth2db packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1757] DSA-1757-1 auth2db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1757-1 auth2db");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'auth2db', release: '5.0', reference: '0.2.5-2+dfsg-1+lenny1');
deb_check(prefix: 'auth2db-common', release: '5.0', reference: '0.2.5-2+dfsg-1+lenny1');
deb_check(prefix: 'auth2db-filters', release: '5.0', reference: '0.2.5-2+dfsg-1+lenny1');
deb_check(prefix: 'auth2db-frontend', release: '5.0', reference: '0.2.5-2+dfsg-1+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
