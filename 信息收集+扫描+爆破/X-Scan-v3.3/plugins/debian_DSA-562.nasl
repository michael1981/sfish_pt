# This script was automatically generated from the dsa-562
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15660);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "562");
 script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-562 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in MySQL, a commonly used SQL
database on Unix servers.  The following problems have been identified
by the Common Vulnerabilities and Exposures Project:
    Oleksandr Byelkin noticed that ALTER TABLE ... RENAME checks
    CREATE/INSERT rights of the old table instead of the new one.
    Lukasz Wojtow noticed a buffer overrun in the mysql_real_connect
    function.
    Dean Ellis noticed that multiple threads ALTERing the same (or
    different) MERGE tables to change the UNION can cause the server
    to crash or stall.
For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-562');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql and related packages and
restart services linking against them (e.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA562] DSA-562-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-562-1 mysql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.8');
deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.8');
deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.8');
deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.8');
deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.8');
deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
