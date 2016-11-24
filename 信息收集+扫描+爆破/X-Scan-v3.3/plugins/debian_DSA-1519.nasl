# This script was automatically generated from the dsa-1519
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31590);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1519");
 script_cve_id("CVE-2008-1284");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1519 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the Horde web application framework permits arbitrary
file inclusion by a remote attacker through the theme preference parameter.
For the old stable distribution (sarge) this problem has been fixed in
version 3.0.4-4sarge7.
For the stable distribution (etch) this problem has been fixed in version
3.1.3-4etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1519');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1519] DSA-1519-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1519-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge7');
deb_check(prefix: 'horde3', release: '4.0', reference: '3.1.3-4etch3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
