# This script was automatically generated from the dsa-1482
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38954);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1482");
 script_cve_id("CVE-2007-6239");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1482 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that malformed cache update replies against the Squid
WWW proxy cache could lead to the exhaustion of system memory, resulting
in potential denial of service.
For the old stable distribution (sarge), the update cannot currently
be processed on the buildd security network due to a bug in the archive
management script. This will be resolved soon. An update for i386
is temporarily available at "http://people.debian.org/~jmm/squid/" /.
For the stable distribution (etch), this problem has been fixed in
version 2.6.5-6etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1482');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1482] DSA-1482-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1482-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '4.0', reference: '2.6.5-6etch1');
deb_check(prefix: 'squid-cgi', release: '4.0', reference: '2.6.5-6etch1');
deb_check(prefix: 'squid-common', release: '4.0', reference: '2.6.5-6etch1');
deb_check(prefix: 'squidclient', release: '4.0', reference: '2.6.5-6etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
