# This script was automatically generated from the dsa-520
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15357);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "520");
 script_cve_id("CVE-2004-0523");
 script_bugtraq_id(10448);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-520 security update');
 script_set_attribute(attribute: 'description', value:
'In their advisory MITKRB5-SA-2004-001, the MIT Kerberos announced the
existence of buffer overflow vulnerabilities in the
krb5_aname_to_localname function.  This function is only used if
aname_to_localname is enabled in the configuration (this is not
enabled by default).
For the current stable distribution (woody), this problem has been
fixed in version 1.2.4-5woody5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-520');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-520
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA520] DSA-520-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-520-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody5');
deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
