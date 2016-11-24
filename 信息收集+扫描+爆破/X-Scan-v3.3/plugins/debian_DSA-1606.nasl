# This script was automatically generated from the dsa-1606
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33467);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1606");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1606 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that poppler, a PDF rendering library, did not 
properly handle embedded fonts in PDF files, allowing attackers to
execute arbitrary code via a crafted font object.
For the stable distribution (etch), this problem has been fixed in version
0.4.5-5.1etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1606');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your poppler package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1606] DSA-1606-1 poppler");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1606-1 poppler");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpoppler-dev', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'libpoppler-glib-dev', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'libpoppler-qt-dev', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'libpoppler0c2', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'libpoppler0c2-glib', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'libpoppler0c2-qt', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'poppler-utils', release: '4.0', reference: '0.4.5-5.1etch3');
deb_check(prefix: 'poppler', release: '4.0', reference: '0.4.5-5.1etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
