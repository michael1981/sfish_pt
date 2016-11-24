# This script was automatically generated from the dsa-1608
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33492);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1608");
 script_cve_id("CVE-2008-2079");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1608 security update');
 script_set_attribute(attribute: 'description', value:
'Sergei Golubchik discovered that MySQL, a widely-deployed database
server, did not properly validate optional data or index directory
paths given in a CREATE TABLE statement, nor would it (under proper
conditions) prevent two databases from using the same paths for data
or index files.  This permits an authenticated user with authorization
to create tables in one database to read, write or delete data from
tables subsequently created in other databases, regardless of other
GRANT authorizations.  The Common Vulnerabilities and Exposures
project identifies this weakness as CVE-2008-2079.
For the stable distribution (etch), this problem has been fixed in
version 5.0.32-7etch6.  Note that the fix applied will have the
consequence of disallowing the selection of data or index paths
under the database root, which on a Debian system is /var/lib/mysql;
database administrators needing to control the placement of these
files under that location must do so through other means.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1608');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql-dfsg-5.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1608] DSA-1608-1 mysql-dfsg-5.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1608-1 mysql-dfsg-5.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient15-dev', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'libmysqlclient15off', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'mysql-client', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'mysql-client-5.0', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'mysql-common', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'mysql-server', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'mysql-server-4.1', release: '4.0', reference: '5.0.32-7etch6');
deb_check(prefix: 'mysql-server-5.0', release: '4.0', reference: '5.0.32-7etch6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
