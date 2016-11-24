# This script was automatically generated from the dsa-534
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15371);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "534");
 script_cve_id("CVE-2002-1581");
 script_bugtraq_id(6055);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-534 security update');
 script_set_attribute(attribute: 'description', value:
'A directory traversal vulnerability was discovered in mailreader
whereby remote attackers could view arbitrary files with the
privileges of the nph-mr.cgi process (by default, www-data) via
relative paths and a null byte in the configLanguage parameter.
For the current stable distribution (woody), this problem has been
fixed in version 2.3.29-5woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-534');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-534
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA534] DSA-534-1 mailreader");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-534-1 mailreader");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mailreader', release: '3.0', reference: '2.3.29-5woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
