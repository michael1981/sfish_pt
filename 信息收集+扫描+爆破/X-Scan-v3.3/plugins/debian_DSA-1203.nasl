# This script was automatically generated from the dsa-1203
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22935);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1203");
 script_cve_id("CVE-2006-5170");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1203 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Rigler discovered that the PAM module for authentication against
LDAP servers processes PasswordPolicyReponse control messages incorrectly,
which might lead to an attacker being able to login into a suspended
system account.
For the stable distribution (sarge) this problem has been fixed in
version 178-1sarge3. Due to technical problems with the security
buildd infrastructure this update lacks a build for the Sun Sparc
architecture. It will be released as soon as the problems are resolved.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1203');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpam-ldap package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1203] DSA-1203-1 libpam-ldap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1203-1 libpam-ldap");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-ldap', release: '3.1', reference: '178-1sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
