# This script was automatically generated from the dsa-478
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15315);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "478");
 script_cve_id("CVE-2004-0183", "CVE-2004-0184");
 script_bugtraq_id(10003, 10003, 10004, 10004);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-478 security update');
 script_set_attribute(attribute: 'description', value:
'tcpdump, a tool for network monitoring and data acquisition, was found
to contain two vulnerabilities whereby tcpdump could be caused to
crash through attempts to read from invalid memory locations.  This
bug is triggered by certain invalid ISAKMP packets.
For the current stable distribution (woody) these problems have been
fixed in version 3.6.2-2.8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-478');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-478
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA478] DSA-478-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-478-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.8');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
