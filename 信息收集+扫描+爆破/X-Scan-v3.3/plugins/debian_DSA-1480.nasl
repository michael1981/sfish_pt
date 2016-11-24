# This script was automatically generated from the dsa-1480
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30188);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1480");
 script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1480 security update');
 script_set_attribute(attribute: 'description', value:
'Alin Rad Pop discovered several buffer overflows in the Poppler PDF
library, which could allow the execution of arbitrary code if a
malformed PDF file is opened.
The old stable distribution (sarge) doesn\'t contain poppler.
For the stable distribution (etch), these problems have been fixed in
version 0.4.5-5.1etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1480');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your poppler packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1480] DSA-1480-1 poppler");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1480-1 poppler");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpoppler-dev', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'libpoppler-glib-dev', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'libpoppler-qt-dev', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'libpoppler0c2', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'libpoppler0c2-glib', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'libpoppler0c2-qt', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'poppler-utils', release: '4.0', reference: '0.4.5-5.1etch2');
deb_check(prefix: 'poppler', release: '4.0', reference: '0.4.5-5.1etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
