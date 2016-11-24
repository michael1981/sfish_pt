# This script was automatically generated from the dsa-381
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15218);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "381");
 script_cve_id("CVE-2003-0780");
 script_bugtraq_id(8590);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-381 security update');
 script_set_attribute(attribute: 'description', value:
'MySQL, a popular relational database system, contains a buffer
overflow condition which could be exploited by a user who has
permission to execute "ALTER TABLE" commands on the tables in the
"mysql" database.  If successfully exploited, this vulnerability
could allow the attacker to execute arbitrary code with the
privileges of the mysqld process (by default, user "mysql").  Since
the "mysql" database is used for MySQL\'s internal record keeping, by
default the mysql administrator "root" is the only user with
permission to alter its tables.
For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-381');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-381
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA381] DSA-381-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-381-1 mysql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
