# This script was automatically generated from the dsa-807
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19682);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "807");
 script_cve_id("CVE-2005-2700");
 script_bugtraq_id(14721);
 script_xref(name: "CERT", value: "744929");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-807 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in mod_ssl, which provides strong
cryptography (HTTPS support) for Apache that allows remote attackers
to bypass access restrictions.
For the old stable distribution (woody) this problem has been fixed in
version 2.8.9-2.5.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.22-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-807');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-ssl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA807] DSA-807-1 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-807-1 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.5');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2.5');
deb_check(prefix: 'libapache-mod-ssl', release: '3.1', reference: '2.8.22-1sarge1');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.1', reference: '2.8.22-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
