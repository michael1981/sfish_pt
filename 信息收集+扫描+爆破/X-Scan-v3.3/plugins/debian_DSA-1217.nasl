# This script was automatically generated from the dsa-1217
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23703);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1217");
 script_cve_id("CVE-2006-5778");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1217 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered that the netkit ftp server switches the user id too
late, which may lead to the bypass of access restrictions when running
on NFS. This update also adds return value checks to setuid() calls, which
may fail in some PAM configurations.
For the stable distribution (sarge) this problem has been fixed in
version 0.17-20sarge2.
For the upcoming stable distribution (etch) this problem has been
fixed in version 0.17-22.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1217');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1217] DSA-1217-1 linux-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1217-1 linux-ftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ftpd', release: '3.1', reference: '0.17-20sarge2');
deb_check(prefix: 'linux-ftpd', release: '4.0', reference: '0.17-22');
deb_check(prefix: 'linux-ftpd', release: '3.1', reference: '0.17-20sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
