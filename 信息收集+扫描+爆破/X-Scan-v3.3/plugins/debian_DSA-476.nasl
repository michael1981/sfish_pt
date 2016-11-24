# This script was automatically generated from the dsa-476
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15313);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "476");
 script_cve_id("CVE-2004-0371");
 script_bugtraq_id(10035);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-476 security update');
 script_set_attribute(attribute: 'description', value:
'According to a security advisory from the heimdal project,
heimdal, a suite of software implementing the Kerberos protocol, has
"a cross-realm vulnerability allowing someone with control over a
realm to impersonate anyone in the cross-realm trust path."
For the current stable distribution (woody) this problem has been
fixed in version 0.4e-7.woody.8.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-476');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-476
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA476] DSA-476-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-476-1 heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
deb_check(prefix: 'heimdal', release: '3.0', reference: '0.4e-7.woody.8.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
