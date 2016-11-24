# This script was automatically generated from the dsa-224
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15061);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "224");
 script_cve_id("CVE-2002-1158", "CVE-2002-1159");
 script_bugtraq_id(6351, 6354);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-224 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in canna, a Japanese
input system.  The Common Vulnerabilities and Exposures (CVE) project
identified the following vulnerabilities:
For the current stable distribution (woody) these problems have been
fixed in version 3.5b2-46.2.
For the old stable distribution (potato) these problems have been
fixed in version 3.5b2-25.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-224');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your canna packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA224] DSA-224-1 canna");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-224-1 canna");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'canna', release: '2.2', reference: '3.5b2-25.2');
deb_check(prefix: 'canna-utils', release: '2.2', reference: '3.5b2-25.2');
deb_check(prefix: 'libcanna1g', release: '2.2', reference: '3.5b2-25.2');
deb_check(prefix: 'libcanna1g-dev', release: '2.2', reference: '3.5b2-25.2');
deb_check(prefix: 'canna', release: '3.0', reference: '3.5b2-46.2');
deb_check(prefix: 'canna-utils', release: '3.0', reference: '3.5b2-46.2');
deb_check(prefix: 'libcanna1g', release: '3.0', reference: '3.5b2-46.2');
deb_check(prefix: 'libcanna1g-dev', release: '3.0', reference: '3.5b2-46.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
