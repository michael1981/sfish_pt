# This script was automatically generated from the dsa-581
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15679);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "581");
 script_cve_id("CVE-2004-0888");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-581 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered several integer overflows in xpdf, a viewer for
PDF files, which can be exploited remotely by a specially crafted PDF
document and lead to the execution of arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 1.00-3.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-581');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xpdf package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA581] DSA-581-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-581-1 xpdf");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.2');
deb_check(prefix: 'xpdf-common', release: '3.0', reference: '1.00-3.2');
deb_check(prefix: 'xpdf-reader', release: '3.0', reference: '1.00-3.2');
deb_check(prefix: 'xpdf-utils', release: '3.0', reference: '1.00-3.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
