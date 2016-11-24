# This script was automatically generated from the dsa-227
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15064);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "227");
 script_cve_id("CVE-2002-1378", "CVE-2002-1379", "CVE-2002-1508");
 script_bugtraq_id(6328, 6620);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-227 security update');
 script_set_attribute(attribute: 'description', value:
'The SuSE Security Team reviewed critical parts of openldap2, an
implementation of the Lightweight Directory Access Protocol (LDAP)
version 2 and 3, and found several buffer overflows and other bugs
remote attackers could exploit to gain access on systems running
vulnerable LDAP servers.  In addition to these bugs, various local
exploitable bugs within the OpenLDAP2 libraries have been fixed.
For the current stable distribution (woody) these problems have been
fixed in version 2.0.23-6.3.
The old stable distribution (potato) does not contain OpenLDAP2
packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-227');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openldap2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA227] DSA-227-1 openldap2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-227-1 openldap2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ldap-gateways', release: '3.0', reference: '2.0.23-6.3');
deb_check(prefix: 'ldap-utils', release: '3.0', reference: '2.0.23-6.3');
deb_check(prefix: 'libldap2', release: '3.0', reference: '2.0.23-6.3');
deb_check(prefix: 'libldap2-dev', release: '3.0', reference: '2.0.23-6.3');
deb_check(prefix: 'slapd', release: '3.0', reference: '2.0.23-6.3');
deb_check(prefix: 'openldap2', release: '3.0', reference: '2.0.23-6.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
