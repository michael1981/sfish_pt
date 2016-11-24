# This script was automatically generated from the dsa-1059
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22601);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1059");
 script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");
 script_bugtraq_id(17808);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1059 security update');
 script_set_attribute(attribute: 'description', value:
'Konstantin Gavrilenko discovered several vulnerabilities in quagga,
the BGP/OSPF/RIP routing daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2006-2223
    Remote attackers may obtain sensitive information via RIPv1
    REQUEST packets even if the quagga has been configured to use MD5
    authentication.
CVE-2006-2224
    Remote attackers could inject arbitrary routes using the RIPv1
    RESPONSE packet even if the quagga has been configured to use MD5
    authentication.
CVE-2006-2276
    Fredrik Widell discovered that local users can cause a denial
    of service in a certain sh ip bgp command entered in the telnet
    interface.
The old stable distribution (woody) does not contain quagga packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.98.3-7.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1059');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your quagga package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1059] DSA-1059-1 quagga");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1059-1 quagga");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'quagga', release: '3.1', reference: '0.98.3-7.2');
deb_check(prefix: 'quagga-doc', release: '3.1', reference: '0.98.3-7.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
