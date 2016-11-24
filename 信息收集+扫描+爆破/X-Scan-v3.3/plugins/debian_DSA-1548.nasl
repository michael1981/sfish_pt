# This script was automatically generated from the dsa-1548
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32003);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1548");
 script_cve_id("CVE-2008-1693");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1548 security update');
 script_set_attribute(attribute: 'description', value:
'Kees Cook discovered a vulnerability in xpdf, a set of tools for
display and conversion of Portable Document Format (PDF) files.  The
Common Vulnerabilities and Exposures project identifies the following
problem:
CVE-2008-1693
    Xpdf\'s handling of embedded fonts lacks sufficient validation
    and type checking.  If a maliciously crafted PDF file is opened, 
    the vulnerability may allow the execution of arbitrary code with
    the privileges of the user running xpdf.
For the stable distribution (etch), these problems have been fixed in
version 3.01-9.1+etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1548');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xpdf package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1548] DSA-1548-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1548-1 xpdf");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xpdf', release: '4.0', reference: '3.01-9.1+etch4');
deb_check(prefix: 'xpdf-common', release: '4.0', reference: '3.01-9.1+etch4');
deb_check(prefix: 'xpdf-reader', release: '4.0', reference: '3.01-9.1+etch4');
deb_check(prefix: 'xpdf-utils', release: '4.0', reference: '3.01-9.1+etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
