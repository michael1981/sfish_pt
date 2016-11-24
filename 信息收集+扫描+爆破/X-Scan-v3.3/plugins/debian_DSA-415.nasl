# This script was automatically generated from the dsa-415
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15252);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "415");
 script_cve_id("CVE-2003-0795", "CVE-2003-0858");
 script_bugtraq_id(9029);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-415 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in zebra, an IP routing daemon:
For the current stable distribution (woody) this problem has been
fixed in version 0.92a-5woody2.
The zebra package has been obsoleted in the unstable distribution by
GNU Quagga, where this problem was fixed in version 0.96.4x-4.
We recommend that you update your zebra package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-415');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-415
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA415] DSA-415-1 zebra");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-415-1 zebra");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'zebra', release: '3.0', reference: '0.92a-5woody2');
deb_check(prefix: 'zebra-doc', release: '3.0', reference: '0.92a-5woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
