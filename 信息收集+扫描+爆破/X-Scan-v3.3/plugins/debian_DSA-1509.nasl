# This script was automatically generated from the dsa-1509
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31170);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1509");
 script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1509 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in xpdf code that is
embedded in koffice, an integrated office suite for KDE.  These flaws
could allow an attacker to execute arbitrary code by inducing the user
to import a specially crafted PDF document.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-4352
Array index error in the DCTStream::readProgressiveDataUnit method in
xpdf/Stream.cc in Xpdf 3.02pl1, as used in poppler, teTeX, KDE, KOffice,
CUPS, and other products, allows remote attackers to trigger memory
corruption and execute arbitrary code via a crafted PDF file.
CVE-2007-5392
Integer overflow in the DCTStream::reset method in xpdf/Stream.cc in
Xpdf 3.02p11 allows remote attackers to execute arbitrary code via a
crafted PDF file, resulting in a heap-based buffer overflow.
CVE-2007-5393
Heap-based buffer overflow in the CCITTFaxStream::lookChar method in
xpdf/Stream.cc in Xpdf 3.02p11 allows remote attackers to execute
arbitrary code via a PDF file that contains a crafted CCITTFaxDecode
filter.
Updates for the old stable distribution (sarge) will be made available
as soon as possible.
For the stable distribution (etch), these problems have been fixed in version
1:1.6.1-2etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1509');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your koffice package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1509] DSA-1509-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1509-1 koffice");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'karbon', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kchart', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kexi', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kformula', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kivio', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kivio-data', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice-data', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice-dbg', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice-dev', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice-doc', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice-doc-html', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koffice-libs', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'koshell', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kplato', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kpresenter', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kpresenter-data', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'krita', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'krita-data', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kspread', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kthesaurus', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kugar', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kword', release: '4.0', reference: '1.6.1-2etch2');
deb_check(prefix: 'kword-data', release: '4.0', reference: '1.6.1-2etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
