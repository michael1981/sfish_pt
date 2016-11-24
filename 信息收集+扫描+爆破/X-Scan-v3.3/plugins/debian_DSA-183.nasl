# This script was automatically generated from the dsa-183
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15020);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "183");
 script_cve_id("CVE-2002-1235");
 script_xref(name: "CERT", value: "875073");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-183 security update');
 script_set_attribute(attribute: 'description', value:
'Tom Yu and Sam Hartman of MIT discovered another stack buffer overflow
in the kadm_ser_wrap_in function in the Kerberos v4 administration
server.  This kadmind bug has a working exploit code circulating,
hence it is considered serious.  The MIT krb5 implementation
includes support for version 4, including a complete v4 library,
server side support for krb4, and limited client support for v4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-183');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA183] DSA-183-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-183-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.4');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody3');
deb_check(prefix: 'ssh-krb5', release: '3.0', reference: '3.4p1-0woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
