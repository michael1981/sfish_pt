# This script was automatically generated from the dsa-1367
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25974);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1367");
 script_cve_id("CVE-2007-3999");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1367 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that a buffer overflow of the RPC library of the MIT
Kerberos reference implementation allows the execution of arbitrary code.
The oldstable distribution (sarge) is not affected by this problem.
For the stable distribution (etch) this problem has been fixed in
version 1.4.4-7etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1367');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Kerberos packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1367] DSA-1367-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1367-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-clients', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-doc', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-ftpd', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-kdc', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-rsh-server', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-telnetd', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5-user', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'libkadm55', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'libkrb5-dbg', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'libkrb5-dev', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'libkrb53', release: '4.0', reference: '1.4.4-7etch3');
deb_check(prefix: 'krb5', release: '4.0', reference: '1.4.4-7etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
