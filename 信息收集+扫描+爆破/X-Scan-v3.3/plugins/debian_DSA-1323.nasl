# This script was automatically generated from the dsa-1323
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25628);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1323");
 script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1323 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the MIT reference
implementation of the Kerberos network authentication protocol suite,
which may lead to the execution of arbitrary code. The Common 
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-2442
    Wei Wang discovered that the free of an uninitialised pointer in the
    Kerberos RPC library may lead to the execution of arbitrary code.
CVE-2007-2443
    Wei Wang discovered that insufficient input sanitising in the
    Kerberos RPC library may lead to the execution of arbitrary code.
CVE-2007-2798
    It was discovered that a buffer overflow in the  Kerberos
    administration daemon may lead to the execution of arbitrary code.
For the old stable distribution (sarge) these problems have been fixed in
version 1.3.6-2sarge5. Packages for hppa, mips and powerpc are not yet
available. They will be provided later.
For the stable distribution (etch) these problems have been fixed in
version 1.4.4-7etch2. Packages for hppa and mips are not yet available.
They will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1323');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Kerberos packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1323] DSA-1323-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1323-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-clients', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-doc', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-ftpd', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-kdc', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-rsh-server', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-telnetd', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-user', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'libkadm55', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'libkrb5-dev', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'libkrb53', release: '3.1', reference: '1.3.6-2sarge5');
deb_check(prefix: 'krb5-admin-server', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-clients', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-doc', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-ftpd', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-kdc', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-rsh-server', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-telnetd', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'krb5-user', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'libkadm55', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'libkrb5-dbg', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'libkrb5-dev', release: '4.0', reference: '1.4.4-7etch2');
deb_check(prefix: 'libkrb53', release: '4.0', reference: '1.4.4-7etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
