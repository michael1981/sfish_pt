# This script was automatically generated from the dsa-885
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22751);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "885");
 script_cve_id("CVE-2005-3393", "CVE-2005-3409");
 script_bugtraq_id(15239);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-885 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in OpenVPN, a free
virtual private network daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2005-3393
    A format string vulnerability has been discovered that could allow
    arbitrary code to be executed on the client.
CVE-2005-3409
    A NULL pointer dereferencing has been discovered that could be
    exploited to crash the service.
The old stable distribution (woody) does not contain openvpn packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-885');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openvpn package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA885] DSA-885-1 openvpn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-885-1 openvpn");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
