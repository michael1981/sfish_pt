# This script was automatically generated from the dsa-1745
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35967);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1745");
 script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1745 security update');
 script_set_attribute(attribute: 'description', value:
'Several security issues have been discovered in lcms, a color management
library. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2009-0581
Chris Evans discovered that lcms is affected by a memory leak, which
could result in a denial of service via specially crafted image files.
CVE-2009-0723
Chris Evans discovered that lcms is prone to several integer overflows
via specially crafted image files, which could lead to the execution of
arbitrary code.
CVE-2009-0733
Chris Evans discovered the lack of upper-bounds check on sizes leading
to a buffer overflow, which could be used to execute arbitrary code.
For the stable distribution (lenny), these problems have been fixed in
version 1.17.dfsg-1+lenny1.
For the oldstable distribution (etch), these problems have been fixed
in version 1.15-1.1+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1745');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lcms packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1745] DSA-1745-1 lcms");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1745-1 lcms");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'liblcms-utils', release: '4.0', reference: '1.15-1.1+etch2');
deb_check(prefix: 'liblcms1', release: '4.0', reference: '1.15-1.1+etch2');
deb_check(prefix: 'liblcms1-dev', release: '4.0', reference: '1.15-1.1+etch2');
deb_check(prefix: 'liblcms-utils', release: '5.0', reference: '1.17.dfsg-1+lenny1');
deb_check(prefix: 'liblcms1', release: '5.0', reference: '1.17.dfsg-1+lenny1');
deb_check(prefix: 'liblcms1-dev', release: '5.0', reference: '1.17.dfsg-1+lenny1');
deb_check(prefix: 'python-liblcms', release: '5.0', reference: '1.17.dfsg-1+lenny1');
deb_check(prefix: 'lcms', release: '4.0', reference: '1.15-1.1+etch2');
deb_check(prefix: 'lcms', release: '5.0', reference: '1.17.dfsg-1+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
