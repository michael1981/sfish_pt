# This script was automatically generated from the dsa-266
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15103);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "266");
 script_cve_id("CVE-2003-0028", "CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0138", "CVE-2003-0139");
 script_xref(name: "CERT", value: "442569");
 script_xref(name: "CERT", value: "516825");
 script_xref(name: "CERT", value: "623217");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-266 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in krb5, an
implementation of MIT Kerberos.
   Kerberos version 5 does not contain this cryptographic
   vulnerability.  Sites are not vulnerable if they have Kerberos v4
   completely disabled, including the disabling of any krb5 to krb4
   translation services.

This version of the krb5 package changes the default behavior and
disallows cross-realm authentication for Kerberos version 4.  Because
of the fundamental nature of the problem, cross-realm authentication
in Kerberos version 4 cannot be made secure and sites should avoid its
use.  A new option (-X) is provided to the krb5kdc and krb524d
commands to re-enable version 4 cross-realm authentication for those
sites that must use this functionality but desire the other security
fixes.

For the stable distribution (woody) this problem has been
fixed in version 1.2.4-5woody4.
The old stable distribution (potato) does not contain krb5 packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-266');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA266] DSA-266-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-266-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody4');
deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
