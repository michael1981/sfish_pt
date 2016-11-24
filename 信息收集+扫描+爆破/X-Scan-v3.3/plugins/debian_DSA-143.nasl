# This script was automatically generated from the dsa-143
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14980);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "143");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);
 script_xref(name: "CERT", value: "192995");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-143 security update');
 script_set_attribute(attribute: 'description', value:
'An integer overflow bug has been discovered in the RPC library used by
the Kerberos 5 administration system, which is derived from the SunRPC
library.  This bug could be exploited to gain unauthorized root access
to a KDC host.  It is believed that the attacker needs to be able to
authenticate to the kadmin daemon for this attack to be successful.
No exploits are known to exist yet.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-143');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kerberos packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA143] DSA-143-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-143-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody1');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
