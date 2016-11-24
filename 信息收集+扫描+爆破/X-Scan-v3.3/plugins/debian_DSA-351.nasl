# This script was automatically generated from the dsa-351
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15188);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "351");
 script_cve_id("CVE-2003-0442");
 script_bugtraq_id(7761);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-351 security update');
 script_set_attribute(attribute: 'description', value:
'The transparent session ID feature in the php4 package does not
properly escape user-supplied input before inserting it into the
generated HTML page.  An attacker could use this vulnerability to
execute embedded scripts within the context of the generated page.
For the stable distribution (woody) this problem has been fixed in
version 4:4.1.2-6woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-351');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-351
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA351] DSA-351-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-351-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-6woody3');
deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-6woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
