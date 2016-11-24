# This script was automatically generated from the dsa-1388
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27515);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "1388");
 script_cve_id("CVE-2007-5365");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1388 security update');
 script_set_attribute(attribute: 'description', value:
'The patch used to correct the DHCP server buffer overflow in DSA-1388-1
was incomplete and did not adequately resolve the problem.  This update
to the previous advisory makes updated packages based on a
newer version of the patch available.
For completeness, please find below the original advisory:
It was discovered that dhcp, a DHCP server for automatic IP address assignment,
didn\'t correctly allocate space for network replies.  This could potentially
allow a malicious DHCP client to execute arbitrary code upon the DHCP server.
<!-- 
For the old stable distribution (sarge), this problem has been fixed in
version 2.0pl5-19.1sarge3.
 -->

For the stable distribution (etch), this problem has been fixed in
version 2.0pl5-19.5etch2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1388');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dhcp packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1388] DSA-1388-3 dhcp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1388-3 dhcp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dhcp', release: '3.1', reference: '2.0pl5-19.5etch2');
deb_check(prefix: 'dhcp-client', release: '3.1', reference: '2.0pl5-19.5etch2');
deb_check(prefix: 'dhcp-relay', release: '3.1', reference: '2.0pl5-19.5etch2');
deb_check(prefix: 'dhcp', release: '4.0', reference: '2.0pl5-19.5etch1');
deb_check(prefix: 'dhcp-client', release: '4.0', reference: '2.0pl5-19.5etch1');
deb_check(prefix: 'dhcp-relay', release: '4.0', reference: '2.0pl5-19.5etch1');
deb_check(prefix: 'dhcp', release: '4.0', reference: '2.0pl5-19.5etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
