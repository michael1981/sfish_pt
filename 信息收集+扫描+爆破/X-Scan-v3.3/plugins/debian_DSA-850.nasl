# This script was automatically generated from the dsa-850
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19958);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "850");
 script_cve_id("CVE-2005-1279");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-850 security update');
 script_set_attribute(attribute: 'description', value:
'"Vade 79" discovered that the BGP dissector in tcpdump, a powerful
tool for network monitoring and data acquisition, does not properly
handle RT_ROUTING_INFO.  A specially crafted BGP packet can cause a
denial of service via an infinite loop.
For the old stable distribution (woody) this problem has been fixed in
version 3.6.2-2.9.
For the stable distribution (sarge) this problem has been fixed in
version 3.8.3-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-850');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tcpdump package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA850] DSA-850-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-850-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.9');
deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.8.3-4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
