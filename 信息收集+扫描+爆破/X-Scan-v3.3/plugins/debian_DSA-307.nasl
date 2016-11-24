# This script was automatically generated from the dsa-307
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15144);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "307");
 script_cve_id("CVE-2003-0360", "CVE-2003-0361", "CVE-2003-0362");
 script_bugtraq_id(7736);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-307 security update');
 script_set_attribute(attribute: 'description', value:
'gPS is a graphical application to watch system processes.  In release
1.1.0 of the gps package, several security vulnerabilities were fixed,
as detailed in the changelog:
All of these problems affect Debian\'s gps package version 0.9.4-1 in
Debian woody.  Debian potato also contains a gps package (version
0.4.1-2), but it is not affected by these problems, as the relevant
functionality is not implemented in that version.
For the stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody1.
The old stable distribution (potato) is not affected by these problems.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-307');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-307
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA307] DSA-307-1 gps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-307-1 gps");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gps', release: '3.0', reference: '0.9.4-1woody1');
deb_check(prefix: 'rgpsp', release: '3.0', reference: '0.9.4-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
