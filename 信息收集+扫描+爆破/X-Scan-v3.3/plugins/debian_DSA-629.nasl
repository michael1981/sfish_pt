# This script was automatically generated from the dsa-629
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16112);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "629");
 script_cve_id("CVE-2004-1189");
 script_xref(name: "CERT", value: "948033");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-629 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been discovered in the MIT Kerberos 5
administration library (libkadm5srv) that could lead to the execution
of arbitrary code upon exploitation by an authenticated user, not
necessarily one with administrative privileges.
For the stable distribution (woody) this problem has been fixed in
version 1.2.4-5woody7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-629');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA629] DSA-629-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-629-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody7');
deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
