# This script was automatically generated from the dsa-1211
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23660);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1211");
 script_cve_id("CVE-2006-4251");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1211 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that malformed TCP packets may lead to denial of service
and possibly the execution of arbitrary code if the PowerDNS nameserver
acts as a recursive nameserver.
For the stable distribution (sarge) this problem has been fixed in
version 2.9.17-13sarge3.
For the upcoming stable distribution (etch) this problem has been fixed
in version 3.1.4-1 of pdns-recursor.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1211');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PowerDNS packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1211] DSA-1211-1 pdns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1211-1 pdns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'pdns', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-backend-geo', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-backend-ldap', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-backend-mysql', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-backend-pgsql', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-backend-pipe', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-backend-sqlite', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-doc', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-recursor', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-server', release: '3.1', reference: '2.9.17-13sarge3');
deb_check(prefix: 'pdns-recursor', release: '4.0', reference: '3.1.4-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
