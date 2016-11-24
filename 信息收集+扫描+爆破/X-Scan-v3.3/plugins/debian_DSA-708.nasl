# This script was automatically generated from the dsa-708
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18053);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "708");
 script_cve_id("CVE-2005-0525");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-708 security update');
 script_set_attribute(attribute: 'description', value:
'An iDEFENSE researcher discovered two problems in the image processing
functions of PHP, a server-side, HTML-embedded scripting language, of
which one is present in PHP3 as well.  When reading a JPEG image, PHP
can be tricked into an endless loop due to insufficient input
validation.
For the stable distribution (woody) this problem has been fixed in
version 3.0.18-23.1woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-708');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA708] DSA-708-1 php3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-708-1 php3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-gd', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-imap', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-ldap', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-magick', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-mhash', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-mysql', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-snmp', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-cgi-xml', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-dev', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-doc', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-gd', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-imap', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-ldap', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-magick', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-mhash', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-mysql', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-snmp', release: '3.0', reference: '3.0.18-23.1woody3');
deb_check(prefix: 'php3-xml', release: '3.0', reference: '3.0.18-23.1woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
