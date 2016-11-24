# This script was automatically generated from the dsa-713
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18115);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "713");
 script_cve_id("CVE-2005-1108", "CVE-2005-1109");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-713 security update');
 script_set_attribute(attribute: 'description', value:
'Several bugs have been found in junkbuster, a HTTP proxy and filter.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities:
    James Ranson discovered that an attacker can modify the referrer
    setting with a carefully crafted URL by accidentally overwriting a
    global variable.
    Tavis Ormandy from the Gentoo Security Team discovered several
    heap corruptions due to inconsistent use of an internal function
    that can crash the daemon or possibly lead to the execution of
    arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 2.0.2-0.2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-713');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your junkbuster package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA713] DSA-713-1 junkbuster");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-713-1 junkbuster");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'junkbuster', release: '3.0', reference: '2.0.2-0.2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
