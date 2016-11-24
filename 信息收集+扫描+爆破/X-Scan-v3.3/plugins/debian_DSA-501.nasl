# This script was automatically generated from the dsa-501
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15338);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "501");
 script_cve_id("CVE-2004-0399", "CVE-2004-0400");
 script_bugtraq_id(10290, 10291);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-501 security update');
 script_set_attribute(attribute: 'description', value:
'Georgi Guninski discovered two stack-based buffer overflows.  They can
not be exploited with the default configuration from the Debian
system, though.  The Common Vulnerabilities and Exposures project
identifies the following problems that are fixed with this update:
    When "sender_verify = true" is configured in exim.conf a buffer
    overflow can happen during verification of the sender.  This
    problem is fixed in exim 4.
    When headers_check_syntax is configured in exim.conf a buffer
    overflow can happen during the header check.  This problem does
    also exist in exim 4.
For the stable distribution (woody) these problems have been fixed in
version 3.35-1woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-501');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your exim package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA501] DSA-501-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-501-1 exim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody3');
deb_check(prefix: 'eximon', release: '3.0', reference: '3.35-1woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
