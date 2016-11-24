# This script was automatically generated from the dsa-1092
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22634);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1092");
 script_cve_id("CVE-2006-2753");
 script_bugtraq_id(18219);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1092 security update');
 script_set_attribute(attribute: 'description', value:
'Josh Berkus and Tom Lane discovered that MySQL 4.1, a popular SQL
database, incorrectly parses a string escaped with mysql_real_escape()
which could lead to SQL injection.  This problem does only exist in
versions 4.1 and 5.0.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.1.11a-4sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1092');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1092] DSA-1092-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1092-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge4');
deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge4');
deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge4');
deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge4');
deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge4');
deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
