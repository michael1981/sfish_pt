# This script was automatically generated from the dsa-1775
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36189);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1775");
 script_cve_id("CVE-2009-1271");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1775 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that php-json-ext, a JSON serialiser for PHP, is
prone to a denial of service attack, when receiving a malformed string
via the json_decode function.
For the oldstable distribution (etch), this problem has been fixed in
version 1.2.1-3.2+etch1.
The stable distribution (lenny) does not contain a separate php-json-ext
package, but includes it in the php5 packages, which will be fixed soon.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1775');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php-json-ext packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1775] DSA-1775-1 php-json-ext");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1775-1 php-json-ext");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'php4-json', release: '4.0', reference: '1.2.1-3.2+etch1');
deb_check(prefix: 'php5-json', release: '4.0', reference: '1.2.1-3.2+etch1');
deb_check(prefix: 'php-json-ext', release: '4.0', reference: '1.2.1-3.2+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
