# This script was automatically generated from the dsa-1218
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23704);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1218");
 script_cve_id("CVE-2006-6171");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1218 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the proftpd FTP daemon performs insufficient
validation of FTP command buffer size limits, which may lead to denial of
service.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.10-15sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1218');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your proftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1218] DSA-1218-1 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1218-1 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.10-15sarge2');
deb_check(prefix: 'proftpd-common', release: '3.1', reference: '1.2.10-15sarge2');
deb_check(prefix: 'proftpd-doc', release: '3.1', reference: '1.2.10-15sarge2');
deb_check(prefix: 'proftpd-ldap', release: '3.1', reference: '1.2.10-15sarge2');
deb_check(prefix: 'proftpd-mysql', release: '3.1', reference: '1.2.10-15sarge2');
deb_check(prefix: 'proftpd-pgsql', release: '3.1', reference: '1.2.10-15sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
