# This script was automatically generated from the dsa-1741
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35992);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1741");
 script_cve_id("CVE-2008-6393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1741 security update');
 script_set_attribute(attribute: 'description', value:
'Jesus Olmos Gonzalez discovered that an integer overflow in the PSI 
Jabber client may lead to remote denial of service.
The old stable distribution (etch) is not affected.
For the stable distribution (lenny), this problem has been fixed in
version 0.11-9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1741');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your psi package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1741] DSA-1741-1 psi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1741-1 psi");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'psi', release: '5.0', reference: '0.11-9');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
