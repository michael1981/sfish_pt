# This script was automatically generated from the dsa-333
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15170);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "333");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-333 security update');
 script_set_attribute(attribute: 'description', value:
'acm, a multi-player aerial combat simulation, uses a network protocol
based on the same RPC implementation used in many C libraries.  This
implementation was found to contain an integer overflow vulnerability
which could be exploited to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 5.0-3.woody.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-333');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-333
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA333] DSA-333-1 acm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-333-1 acm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'acm', release: '3.0', reference: '5.0-3.woody.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
