# This script was automatically generated from the dsa-425
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15262);
 script_version("$Revision: 1.15 $");
 script_xref(name: "DSA", value: "425");
 script_bugtraq_id(9263);
 script_bugtraq_id(9507);
 script_xref(name: "CERT", value: "174086");
 script_xref(name: "CERT", value: "738518");
 script_xref(name: "CERT", value: "955526");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-425 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities were discovered in tcpdump, a tool for
inspecting network traffic.  If a vulnerable version of tcpdump
attempted to examine a maliciously constructed packet, a number of
buffer overflows could be exploited to crash tcpdump, or potentially
execute arbitrary code with the privileges of the tcpdump process.
For the current stable distribution (woody) these problems have been
fixed in version 3.6.2-2.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-425');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-425
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA425] DSA-425-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0055", "CVE-2004-0057");
 script_summary(english: "DSA-425-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
