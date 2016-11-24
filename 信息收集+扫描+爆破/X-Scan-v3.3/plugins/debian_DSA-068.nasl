# This script was automatically generated from the dsa-068
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14905);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "068");
 script_cve_id("CVE-2001-0977");
 script_bugtraq_id(3049);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-068 security update');
 script_set_attribute(attribute: 'description', value:
'The CERT advisory  lists a number of vulnerabilities in various
LDAP implementations, based on the 
results of the PROTOS LDAPv3 test suite. These tests found one
problem in OpenLDAP, a free LDAP implementation which is shipped
as part of Debian GNU/Linux 2.2.

The problem is that slapd did not handle packets which had
BER fields of invalid length and would crash if it received them.
An attacker could use this to mount a remote denial of service attack.

This problem has been fixed in version 1.2.12-1, and we recommend
that you upgrade your slapd package immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-068');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-068
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA068] DSA-068-1 openldap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-068-1 openldap");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ldap-rfc', release: '2.2', reference: '1.2.12-1');
deb_check(prefix: 'libopenldap-dev', release: '2.2', reference: '1.2.12-1');
deb_check(prefix: 'libopenldap-runtime', release: '2.2', reference: '1.2.12-1');
deb_check(prefix: 'libopenldap1', release: '2.2', reference: '1.2.12-1');
deb_check(prefix: 'openldap-gateways', release: '2.2', reference: '1.2.12-1');
deb_check(prefix: 'openldap-utils', release: '2.2', reference: '1.2.12-1');
deb_check(prefix: 'openldapd', release: '2.2', reference: '1.2.12-1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
