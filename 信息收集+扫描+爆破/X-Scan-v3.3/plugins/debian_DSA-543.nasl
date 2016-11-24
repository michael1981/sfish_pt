# This script was automatically generated from the dsa-543
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15380);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "543");
 script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");
 script_xref(name: "CERT", value: "350792");
 script_xref(name: "CERT", value: "550464");
 script_xref(name: "CERT", value: "795632");
 script_xref(name: "CERT", value: "866472");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-543 security update');
 script_set_attribute(attribute: 'description', value:
'The MIT Kerberos Development Team has discovered a number of
vulnerabilities in the MIT Kerberos Version 5 software.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    A double-free error may allow unauthenticated remote attackers to
    execute arbitrary code on KDC or clients.
    Several double-free errors may allow authenticated attackers to
    execute arbitrary code on Kerberos application servers.
    A remotely exploitable denial of service vulnerability has been
    found in the KDC and libraries.
    Several double-free errors may allow remote attackers to execute
    arbitrary code on the server.  This does not affect the version in
    woody.
For the stable distribution (woody) these problems have been fixed in
version 1.2.4-5woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-543');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA543] DSA-543-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-543-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody6');
deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
