# This script was automatically generated from the dsa-474
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15311);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "474");
 script_cve_id("CVE-2004-0189");
 script_bugtraq_id(9778);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-474 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in squid, an Internet object cache,
whereby access control lists based on URLs could be bypassed
(CVE-2004-0189).  Two other bugs were also fixed with patches
squid-2.4.STABLE7-url_escape.patch (a buffer overrun which does not
appear to be exploitable) and squid-2.4.STABLE7-url_port.patch (a
potential denial of service).
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-474');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-474
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA474] DSA-474-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-474-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody2');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody2');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
