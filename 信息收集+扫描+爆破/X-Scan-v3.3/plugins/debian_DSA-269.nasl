# This script was automatically generated from the dsa-269
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15106);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "269");
 script_cve_id("CVE-2003-0138");
 script_xref(name: "CERT", value: "623217");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-269 security update');
 script_set_attribute(attribute: 'description', value:
'A cryptographic weakness in version 4 of the Kerberos protocol allows
an attacker to use a chosen-plaintext attack to impersonate any
principal in a realm.  Additional cryptographic weaknesses in the krb4
implementation permit the use of cut-and-paste attacks to fabricate
krb4 tickets for unauthorized client principals if triple-DES keys are
used to key krb4 services.  These attacks can subvert a site\'s entire
Kerberos authentication infrastructure.
This version of the heimdal package changes the default behavior and
disallows cross-realm authentication for Kerberos version 4.  Because
of the fundamental nature of the problem, cross-realm authentication
in Kerberos version 4 cannot be made secure and sites should avoid its
use.  A new option (--kerberos4-cross-realm) is provided to the kdc 
command to re-enable version 4 cross-realm authentication for those
sites that must use this functionality but desire the other security
fixes.
For the stable distribution (woody) this problem has been
fixed in version 0.4e-7.woody.8.
The old stable distribution (potato) is not affected by this problem,
since it isn\'t compiled against kerberos 4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-269');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heimdal packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA269] DSA-269-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-269-1 heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.8');
deb_check(prefix: 'heimdal', release: '3.0', reference: '0.4e-7.woody.8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
