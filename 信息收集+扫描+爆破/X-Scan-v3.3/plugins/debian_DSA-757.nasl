# This script was automatically generated from the dsa-757
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19219);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "757");
 script_cve_id("CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
 script_xref(name: "CERT", value: "259798");
 script_xref(name: "CERT", value: "623332");
 script_xref(name: "CERT", value: "885830");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-757 security update');
 script_set_attribute(attribute: 'description', value:
'Daniel Wachdorf reported two problems in the MIT krb5 distribution used
for network authentication. First, the KDC program from the krb5-kdc
package can corrupt the heap by trying to free memory which has already
been freed on receipt of a certain TCP connection. This vulnerability
can cause the KDC to crash, leading to a denial of service.
[CVE-2005-1174] Second, under certain rare circumstances this type of
request can lead to a buffer overflow and remote code execution.
[CVE-2005-1175] 
Additionally, Magnus Hagander reported another problem in which the
krb5_recvauth function can in certain circumstances free previously
freed memory, potentially leading to the execution of remote code.
[CVE-2005-1689] 
All of these vulnerabilities are believed difficult to exploit, and no
exploits have yet been discovered.
For the old stable distribution (woody), these problems have been fixed
in version 1.2.4-5woody10. Note that woody\'s KDC does not have TCP
support and is not vulnerable to CVE-2005-1174.
For the stable distribution (sarge), these problems have been fixed in
version 1.3.6-2sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-757');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA757] DSA-757-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-757-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody10');
deb_check(prefix: 'krb5-admin-server', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-clients', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-doc', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-ftpd', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-kdc', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-rsh-server', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-telnetd', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5-user', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'libkadm55', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'libkrb5-dev', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'libkrb53', release: '3.1', reference: '1.3.6-2sarge2');
deb_check(prefix: 'krb5', release: '3.1', reference: '1.3.6-2sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
