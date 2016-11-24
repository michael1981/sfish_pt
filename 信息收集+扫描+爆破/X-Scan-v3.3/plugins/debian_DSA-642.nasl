# This script was automatically generated from the dsa-642
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16182);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "642");
 script_cve_id("CVE-2004-1106");
 script_bugtraq_id(11602);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-642 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in gallery, a web-based
photo album written in PHP4.  The Common Vulnerabilities and Exposures
project identifies the following vulnerabilities:
    Jim Paris discovered a cross site scripting vulnerability which
    allows code to be inserted by using specially formed URLs.
    The upstream developers of gallery have fixed several cases of
    possible variable injection that could trick gallery to unintended
    actions, e.g. leaking database passwords.
For the stable distribution (woody) these problems have been fixed in
version 1.2.5-8woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-642');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gallery package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA642] DSA-642-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-642-1 gallery");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
