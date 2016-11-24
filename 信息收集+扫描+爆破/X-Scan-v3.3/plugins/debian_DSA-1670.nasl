# This script was automatically generated from the dsa-1670
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34949);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1670");
 script_cve_id("CVE-2008-3863", "CVE-2008-4306");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1670 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Enscript, a converter
from ASCII text to Postscript, HTML or RTF. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2008-3863
   Ulf Harnhammer discovered that a buffer overflow may lead to
   the execution of arbitrary code.
CVE-2008-4306
   Kees Cook and Tomas Hoger discovered that several buffer
   overflows may lead to the execution of arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 1.6.4-11.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1670');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your enscript package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1670] DSA-1670-1 enscript");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1670-1 enscript");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'enscript', release: '4.0', reference: '1.6.4-11.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
