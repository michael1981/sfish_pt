# This script was automatically generated from the dsa-1785
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38666);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1785");
 script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1785 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to denial of service or the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-1210
    A format string vulnerability was discovered in the PROFINET
    dissector.
CVE-2009-1268
    The dissector for the Check Point High-Availability Protocol
    could be forced to crash.
CVE-2009-1269
    Malformed Tektronix files could lead to a crash.
The old stable distribution (etch), is only affected by the
CPHAP crash, which doesn\'t warrant an update on its own. The fix
will be queued up for an upcoming security update or a point release.
For the stable distribution (lenny), these problems have been fixed in
version 1.0.2-3+lenny5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1785');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wireshark packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1785] DSA-1785-1 wireshark");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1785-1 wireshark");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tshark', release: '5.0', reference: '1.0.2-3+lenny5');
deb_check(prefix: 'wireshark', release: '5.0', reference: '1.0.2-3+lenny5');
deb_check(prefix: 'wireshark-common', release: '5.0', reference: '1.0.2-3+lenny5');
deb_check(prefix: 'wireshark-dev', release: '5.0', reference: '1.0.2-3+lenny5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
