# This script was automatically generated from the dsa-963
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22829);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "963");
 script_cve_id("CVE-2006-0351");
 script_bugtraq_id(16431);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-963 security update');
 script_set_attribute(attribute: 'description', value:
'NISCC reported that MyDNS, a DNS server using an SQL database for data
storage, can be tricked into an infinite loop by a remote attacker and
hence cause a denial of service condition.
The old stable distribution (woody) does not contain mydns packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.0-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-963');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mydns package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA963] DSA-963-1 mydns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-963-1 mydns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mydns-common', release: '3.1', reference: '1.0.0-4sarge1');
deb_check(prefix: 'mydns-mysql', release: '3.1', reference: '1.0.0-4sarge1');
deb_check(prefix: 'mydns-pgsql', release: '3.1', reference: '1.0.0-4sarge1');
deb_check(prefix: 'mydns', release: '3.1', reference: '1.0.0-4sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
