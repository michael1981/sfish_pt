# This script was automatically generated from the dsa-273
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15110);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "273");
 script_cve_id("CVE-2003-0138", "CVE-2003-0139");
 script_xref(name: "CERT", value: "442569");
 script_xref(name: "CERT", value: "623217");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-273 security update');
 script_set_attribute(attribute: 'description', value:
'A cryptographic weakness in version 4 of the Kerberos protocol allows
an attacker to use a chosen-plaintext attack to impersonate any
principal in a realm.  Additional cryptographic weaknesses in the krb4
implementation permit the use of cut-and-paste attacks to fabricate
krb4 tickets for unauthorized client principals if triple-DES keys are
used to key krb4 services.  These attacks can subvert a site\'s entire
Kerberos authentication infrastructure.
For the stable distribution (woody) this problem has been
fixed in version 1.1-8-2.3.
For the old stable distribution (potato) this problem has been
fixed in version 1.0-2.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-273');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb4 packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA273] DSA-273-1 krb4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-273-1 krb4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kerberos4kth-clients', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth-dev', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth-kdc', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth-services', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth-user', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth-x11', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth1', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'kerberos4kth-clients', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-clients-x', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-dev', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-dev-common', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-docs', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-kdc', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-kip', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-servers', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-servers-x', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-services', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-user', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth-x11', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'kerberos4kth1', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'libacl1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'libkadm1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'libkdb-1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'libkrb-1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3');
deb_check(prefix: 'krb4', release: '2.2', reference: '1.0-2.3');
deb_check(prefix: 'krb4', release: '3.0', reference: '1.1-8-2.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
