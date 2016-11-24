# This script was automatically generated from the dsa-185
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15022);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "185");
 script_cve_id("CVE-2002-1235");
 script_xref(name: "CERT", value: "875073");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-185 security update');
 script_set_attribute(attribute: 'description', value:
'A stack buffer overflow in the kadm_ser_wrap_in function in the
Kerberos v4 administration server was discovered, which is provided by
Heimdal as well.  A working exploit for this kadmind bug is already
circulating, hence it is considered serious.  The broken library also
contains a vulnerability which could lead to another root exploit.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-185');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heimdal packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA185] DSA-185-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-185-1 heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heimdal-clients', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-clients-x', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-dev', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-docs', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-kdc', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-lib', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-servers', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-servers-x', release: '2.2', reference: '0.2l-7.6');
deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
