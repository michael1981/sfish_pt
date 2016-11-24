# This script was automatically generated from the dsa-1675
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35010);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1675");
 script_cve_id("CVE-2008-4326");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1675 security update');
 script_set_attribute(attribute: 'description', value:
'Masako Oono discovered that phpMyAdmin, a web-based administration
interface for MySQL, insufficiently sanitises input allowing a
remote attacker to gather sensitive data through cross site scripting,
provided that the user uses the Internet Explorer web browser.
This update also fixes a regression introduced in DSA 1641, that
broke changing of the language and encoding in the login screen.
For the stable distribution (etch), these problems have been fixed in
version 4:2.9.1.1-9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1675');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1675] DSA-1675-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1675-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '4.0', reference: '2.9.1.1-9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
