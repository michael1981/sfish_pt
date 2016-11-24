# This script was automatically generated from the dsa-934
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22800);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "934");
 script_cve_id("CVE-2005-1391", "CVE-2005-3751");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-934 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in Pound, a reverse proxy and
load balancer for HTTP. The Common Vulnerabilities and Exposures project
identifies the following problems:
     Overly long HTTP Host: headers may trigger a buffer overflow in the
     add_port() function, which may lead to the execution of arbitrary
     code.
     HTTP requests with conflicting Content-Length and Transfer-Encoding
     headers could lead to HTTP Request Smuggling Attack, which can be
     exploited to bypass packet filters or poison web caches.
The old stable distribution (woody) does not contain pound packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.8.2-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-934');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pound package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA934] DSA-934-1 pound");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-934-1 pound");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'pound', release: '3.1', reference: '1.8.2-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
