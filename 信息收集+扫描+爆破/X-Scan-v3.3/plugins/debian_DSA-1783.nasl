# This script was automatically generated from the dsa-1783
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38642);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1783");
 script_cve_id("CVE-2008-3963", "CVE-2008-4456");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1783 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been identified affecting MySQL, a
relational database server, and its associated interactive client
application.  The Common Vulnerabilities and Exposures project
identifies the following two problems:
CVE-2008-3963
    Kay Roepke reported that the MySQL server would not properly handle
    an empty bit-string literal in an SQL statement, allowing an
    authenticated remote attacker to cause a denial of service (a crash)
    in mysqld.  This issue affects the oldstable distribution (etch), but
    not the stable distribution (lenny).
CVE-2008-4456
    Thomas Henlich reported that the MySQL commandline client application
    did not encode HTML special characters when run in HTML output mode
    (that is, "mysql --html ...").  This could potentially lead to
    cross-site scripting or unintended script privilege escalation if
    the resulting output is viewed in a browser or incorporated into
    a web site.
For the old stable distribution (etch), these problems have been fixed in
version 5.0.32-7etch10.
For the stable distribution (lenny),  these problems have been fixed in
version 5.0.51a-24+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1783');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql-dfsg-5.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1783] DSA-1783-1 mysql-dfsg-5.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1783-1 mysql-dfsg-5.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient15-dev', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'libmysqlclient15off', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-client', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-client-5.0', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-common', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-server', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-server-4.1', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-server-5.0', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'libmysqlclient15-dev', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'libmysqlclient15off', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'mysql-client', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'mysql-client-5.0', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'mysql-common', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'mysql-server', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'mysql-server-5.0', release: '5.0', reference: '5.0.51a-24+lenny1');
deb_check(prefix: 'mysql-dfsg-5.0', release: '4.0', reference: '5.0.32-7etch10');
deb_check(prefix: 'mysql-dfsg-5.0', release: '5.0', reference: '5.0.51a-24+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
