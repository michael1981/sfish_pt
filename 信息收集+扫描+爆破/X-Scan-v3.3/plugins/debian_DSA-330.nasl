# This script was automatically generated from the dsa-330
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15167);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "330");
 script_cve_id("CVE-2003-0489");
 script_bugtraq_id(8020);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-330 security update');
 script_set_attribute(attribute: 'description', value:
'tcptraceroute is a setuid-root program which drops root privileges
after obtaining a file descriptor used for raw packet capture.
However, it did not fully relinquish all privileges, and in the event
of an exploitable vulnerability, root privileges could be regained.
No current exploit is known, but this safeguard is being repaired in
order to provide a measure of containment in the event that an
exploitable flaw should be discovered.
For the stable distribution (woody) this problem has been fixed in
version 1.2-2.
The old stable distribution (potato) does not contain a tcptraceroute
package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-330');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-330
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA330] DSA-330-1 tcptraceroute");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-330-1 tcptraceroute");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tcptraceroute', release: '3.0', reference: '1.2-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
