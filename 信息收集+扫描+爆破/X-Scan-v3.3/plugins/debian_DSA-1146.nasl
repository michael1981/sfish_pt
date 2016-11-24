# This script was automatically generated from the dsa-1146
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22688);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1146");
 script_cve_id("CVE-2006-3083", "CVE-2006-3084");
 script_xref(name: "CERT", value: "401660");
 script_xref(name: "CERT", value: "580124");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1146 security update');
 script_set_attribute(attribute: 'description', value:
'In certain application programs packaged in the MIT Kerberos 5 source
distribution, calls to setuid() and seteuid() are not always checked
for success and may fail with some PAM configurations.  A local
user could exploit one of these vulnerabilities to result in privilege
escalation.  No exploit code is known to exist at this time.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.6-2sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1146');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1146] DSA-1146-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1146-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-clients', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-doc', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-ftpd', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-kdc', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-rsh-server', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-telnetd', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5-user', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'libkadm55', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'libkrb5-dev', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'libkrb53', release: '3.1', reference: '1.3.6-2sarge3');
deb_check(prefix: 'krb5', release: '3.1', reference: '1.3.6-2sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
