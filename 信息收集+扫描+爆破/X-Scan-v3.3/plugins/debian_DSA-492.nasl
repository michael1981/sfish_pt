# This script was automatically generated from the dsa-492
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15329);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "492");
 script_cve_id("CVE-2003-0856");
 script_bugtraq_id(9092);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-492 security update');
 script_set_attribute(attribute: 'description', value:
'Herbert Xu reported that local users could cause a denial of service
against iproute, a set of tools for controlling networking in Linux
kernels.  iproute uses the netlink interface to communicate with the
kernel, but failed to verify that the messages it received came from
the kernel (rather than from other user processes).
For the current stable distribution (woody) this problem has been
fixed in version 20010824-8woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-492');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-492
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA492] DSA-492-1 iproute");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-492-1 iproute");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'iproute', release: '3.0', reference: '20010824-8woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
