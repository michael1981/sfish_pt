# This script was automatically generated from the dsa-1057
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22599);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1057");
 script_cve_id("CVE-2006-2016");
 script_bugtraq_id(17643);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1057 security update');
 script_set_attribute(attribute: 'description', value:
'Several cross-site scripting vulnerabilities have been discovered in
phpLDAPadmin, a web based interface for administering LDAP servers,
that allows remote attackers to inject arbitrary web script or HTML.
The old stable distribution (woody) does not contain phpldapadmin
packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.5-3sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1057');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpldapadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1057] DSA-1057-1 phpldapadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1057-1 phpldapadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpldapadmin', release: '3.1', reference: '0.9.5-3sarge3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
