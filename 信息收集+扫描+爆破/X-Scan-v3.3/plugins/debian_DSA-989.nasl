# This script was automatically generated from the dsa-989
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22855);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "989");
 script_cve_id("CVE-2006-0402");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-989 security update');
 script_set_attribute(attribute: 'description', value:
'Neil McBride discovered that Zoph, a web based photo management system
performs insufficient sanitising for input passed to photo searches, which
may lead to the execution of SQL commands through a SQL injection attack.
The old stable distribution (woody) does not contain zoph packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.3.3-12sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-989');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your zoph package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA989] DSA-989-1 zoph");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-989-1 zoph");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'zoph', release: '3.1', reference: '0.3.3-12sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
