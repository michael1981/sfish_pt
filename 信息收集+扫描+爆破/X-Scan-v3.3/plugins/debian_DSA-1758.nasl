# This script was automatically generated from the dsa-1758
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36067);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1758");
 script_cve_id("CVE-2009-1073");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1758 security update');
 script_set_attribute(attribute: 'description', value:
'Leigh James discovered that nss-ldapd, an NSS module for using
LDAP as a naming service, by default creates the configuration file
/etc/nss-ldapd.conf world-readable which could leak the configured
LDAP password if one is used for connecting to the LDAP server.
The old stable distribution (etch) doesn\'t contain nss-ldapd.
For the stable distribution (lenny) this problem has been fixed in
version 0.6.7.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1758');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your nss-ldapd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1758] DSA-1758-1 nss-ldapd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1758-1 nss-ldapd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnss-ldapd', release: '5.0', reference: '0.6.7.1');
deb_check(prefix: 'nss-ldapd', release: '5.0', reference: '0.6.7.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
