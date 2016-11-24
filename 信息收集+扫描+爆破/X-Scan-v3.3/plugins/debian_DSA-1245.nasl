# This script was automatically generated from the dsa-1245
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25339);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1245");
 script_cve_id("CVE-2005-4816");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1245 security update');
 script_set_attribute(attribute: 'description', value:
'Martin Loewer discovered that the proftpd FTP daemon is vulnerable to
denial of service if the addon module for Radius authentication is enabled.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.10-15sarge4.
For the upcoming stable distribution (etch) this problem has been
fixed in version 1.2.10+1.3.0rc5-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1245');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your proftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1245] DSA-1245-1 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1245-1 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.10-15sarge4');
deb_check(prefix: 'proftpd-common', release: '3.1', reference: '1.2.10-15sarge4');
deb_check(prefix: 'proftpd-doc', release: '3.1', reference: '1.2.10-15sarge4');
deb_check(prefix: 'proftpd-ldap', release: '3.1', reference: '1.2.10-15sarge4');
deb_check(prefix: 'proftpd-mysql', release: '3.1', reference: '1.2.10-15sarge4');
deb_check(prefix: 'proftpd-pgsql', release: '3.1', reference: '1.2.10-15sarge4');
deb_check(prefix: 'proftpd', release: '4.0', reference: '1.2.10+1.3.0rc5-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
