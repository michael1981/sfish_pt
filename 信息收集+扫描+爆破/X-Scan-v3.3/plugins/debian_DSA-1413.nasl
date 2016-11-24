# This script was automatically generated from the dsa-1413
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(28336);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1413");
 script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1413 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in the MySQL database packages
with implications ranging from unauthorized database modifications to
remotely triggered server crashes.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2007-2583
	The in_decimal::set function in item_cmpfunc.cc in MySQL
	before 5.0.40 allows context-dependent attackers to cause a
	denial of service (crash) via a crafted IF clause that results
	in a divide-by-zero error and a NULL pointer dereference.
	(Affects source version 5.0.32.)
CVE-2007-2691
	MySQL does not require the DROP privilege for RENAME TABLE
	statements, which allows remote authenticated users to rename
	arbitrary tables. (All supported versions affected.)
CVE-2007-2692
	The mysql_change_db function does not restore THD::db_access
	privileges when returning from SQL SECURITY INVOKER stored
	routines, which allows remote authenticated users to gain
	privileges.  (Affects source version 5.0.32.)
CVE-2007-3780
	MySQL could be made to overflow a signed char during
	authentication. Remote attackers could use specially crafted
	authentication requests to cause a denial of
	service. (Upstream source versions 4.1.11a and 5.0.32
	affected.)
CVE-2007-3782
	Phil Anderton discovered that MySQL did not properly verify
	access privileges when accessing external tables. As a result,
	authenticated users could exploit this to obtain UPDATE
	privileges to external tables.  (Affects source version
	5.0.32.)
CVE-2007-5925
	The convert_search_mode_to_innobase function in ha_innodb.cc
	in the InnoDB engine in MySQL 5.1.23-BK and earlier allows
	remote authenticated users to cause a denial of service
	(database crash) via a certain CONTAINS operation on an
	indexed column, which triggers an assertion error.  (Affects
	source version 5.0.32.)
For the old stable distribution (sarge), these problems have been fixed in
version 4.0.24-10sarge3 of mysql-dfsg and version 4.1.11a-4sarge8 of
mysql-dfsg-4.1.
For the stable distribution (etch), these problems have been fixed in
version 5.0.32-7etch3 of the mysql-dfsg-5.0 packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1413');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1413] DSA-1413-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1413-1 mysql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient12', release: '3.1', reference: '4.0.24-10sarge3');
deb_check(prefix: 'libmysqlclient12-dev', release: '3.1', reference: '4.0.24-10sarge3');
deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge8');
deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge8');
deb_check(prefix: 'mysql-client', release: '3.1', reference: '4.0.24-10sarge3');
deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge8');
deb_check(prefix: 'mysql-common', release: '3.1', reference: '4.0.24-10sarge3');
deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge8');
deb_check(prefix: 'mysql-server', release: '3.1', reference: '4.0.24-10sarge3');
deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge8');
deb_check(prefix: 'libmysqlclient15-dev', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'libmysqlclient15off', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'mysql-client', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'mysql-client-5.0', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'mysql-common', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'mysql-server', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'mysql-server-4.1', release: '4.0', reference: '5.0.32-7etch3');
deb_check(prefix: 'mysql-server-5.0', release: '4.0', reference: '5.0.32-7etch3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
