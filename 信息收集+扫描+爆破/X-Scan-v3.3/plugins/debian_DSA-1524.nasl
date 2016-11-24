# This script was automatically generated from the dsa-1524
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31630);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1524");
 script_cve_id("CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1524 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the kdc component
of the krb5, a system for authenticating users and services on a
network. The Common Vulnerabilities and Exposures project identifies the 
following problems:
CVE-2008-0062
An unauthenticated remote attacker may cause a krb4-enabled KDC to
crash, expose information, or execute arbitrary code.  Successful
exploitation of this vulnerability could compromise the Kerberos key
database and host security on the KDC host.
CVE-2008-0063
An unauthenticated remote attacker may cause a krb4-enabled KDC to
expose information.  It is theoretically possible for the exposed
information to include secret key data on some platforms.
CVE-2008-0947
An unauthenticated remote attacker can cause memory corruption in the
kadmind process, which is likely to cause kadmind to crash, resulting in
a denial of service. It is at least theoretically possible for such
corruption to result in database corruption or arbitrary code execution,
though we have no such exploit and are not aware of any such exploits in
use in the wild.  In versions of MIT Kerberos shipped by Debian, this
bug can only be triggered in configurations that allow large numbers of
open file descriptors in a process.
For the old stable distribution (sarge), these problems have been fixed
in version krb5 1.3.6-2sarge6.
For the stable distribution (etch), these problems have been fixed in
version 1.4.4-7etch5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1524');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1524] DSA-1524-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1524-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-clients', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-doc', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-ftpd', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-kdc', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-rsh-server', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-telnetd', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-user', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'libkadm55', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'libkrb5-dev', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'libkrb53', release: '3.1', reference: '1.3.6-2sarge6');
deb_check(prefix: 'krb5-admin-server', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-clients', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-doc', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-ftpd', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-kdc', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-rsh-server', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-telnetd', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5-user', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'libkadm55', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'libkrb5-dbg', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'libkrb5-dev', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'libkrb53', release: '4.0', reference: '1.4.4-7etch5');
deb_check(prefix: 'krb5', release: '4.0', reference: '1.4.4-7etch5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
