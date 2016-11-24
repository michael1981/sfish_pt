# This script was automatically generated from the dsa-1434
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29707);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1434");
 script_cve_id("CVE-2007-2362");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1434 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that in MyDNS, a domain name server with database
backend, the daemon could be crashed through malicious remote update
requests, which may lead to denial of service.


The old stable distribution (sarge) is not affected.


For the stable distribution (etch), this problem has been fixed in
version 1:1.1.0-7etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1434');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mydns packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1434] DSA-1434-1 mydns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1434-1 mydns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mydns-mysql', release: '4.0', reference: '1.1.0-7etch1');
deb_check(prefix: 'mydns-pgsql', release: '4.0', reference: '1.1.0-7etch1');
deb_check(prefix: 'mydns', release: '4.0', reference: '1.1.0-7etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
