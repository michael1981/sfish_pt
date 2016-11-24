# This script was automatically generated from the dsa-1732
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35763);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1732");
 script_cve_id("CVE-2009-0478");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1732 security update');
 script_set_attribute(attribute: 'description', value:
'Joshua Morin, Mikko Varpiola and Jukka Taimisto discovered an assertion
error in squid3, a full featured Web Proxy cache, which could lead to
a denial of service attack.
For the oldstable distribution (etch), this problem has been fixed in
version 3.0.PRE5-5+etch1.
For the stable distribution (lenny), this problem has been fixed in
version 3.0.STABLE8-3, which was already included in the lenny release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1732');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2009/dsa-1732
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1732] DSA-1732-1 squid3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1732-1 squid3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid3', release: '4.0', reference: '3.0.PRE5-5+etch1');
deb_check(prefix: 'squid3-cgi', release: '4.0', reference: '3.0.PRE5-5+etch1');
deb_check(prefix: 'squid3-client', release: '4.0', reference: '3.0.PRE5-5+etch1');
deb_check(prefix: 'squid3-common', release: '4.0', reference: '3.0.PRE5-5+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
