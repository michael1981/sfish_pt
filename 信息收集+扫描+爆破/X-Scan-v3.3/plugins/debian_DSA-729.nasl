# This script was automatically generated from the dsa-729
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18516);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "729");
 script_cve_id("CVE-2005-0525");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-729 security update');
 script_set_attribute(attribute: 'description', value:
'An iDEFENSE researcher discovered two problems in the image processing
functions of PHP, a server-side, HTML-embedded scripting language, of
which one is present in woody as well.  When reading a JPEG image, PHP
can be tricked into an endless loop due to insufficient input
validation.
For the stable distribution (woody) this problem has been fixed in
version 4.1.2-7.woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-729');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php4 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA729] DSA-729-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-729-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-7.woody4');
deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-7.woody4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
