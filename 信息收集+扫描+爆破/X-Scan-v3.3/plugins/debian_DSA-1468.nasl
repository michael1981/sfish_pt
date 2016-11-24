# This script was automatically generated from the dsa-1468
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30060);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1468");
 script_cve_id("CVE-2007-2450", "CVE-2008-0128");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1468 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Tomcat
servlet and JSP engine. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-0128
    Olaf Kock discovered that HTTPS encryption was insufficiently
    enforced for single-sign-on cookies, which could result in
    information disclosure.
CVE-2007-2450
    It was discovered that the Manager and Host Manager web applications
    performed insufficient input sanitising, which could lead to cross site
    scripting.
This update also adapts the tomcat5.5-webapps package to the tightened
JULI permissions introduced in the previous tomcat5.5 DSA. However, it
should be noted, that the tomcat5.5-webapps is for demonstration and
documentation purposes only and should not be used for production
systems.
The old stable distribution (sarge) doesn\'t contain tomcat5.5.
For the stable distribution (etch), these problems have been fixed in
version 5.5.20-2etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1468');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tomcat5.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1468] DSA-1468-1 tomcat5.5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1468-1 tomcat5.5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtomcat5.5-java', release: '4.0', reference: '5.5.20-2etch2');
deb_check(prefix: 'tomcat5.5', release: '4.0', reference: '5.5.20-2etch2');
deb_check(prefix: 'tomcat5.5-admin', release: '4.0', reference: '5.5.20-2etch2');
deb_check(prefix: 'tomcat5.5-webapps', release: '4.0', reference: '5.5.20-2etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
