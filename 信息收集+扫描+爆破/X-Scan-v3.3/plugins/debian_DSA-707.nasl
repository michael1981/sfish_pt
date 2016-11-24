# This script was automatically generated from the dsa-707
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18042);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "707");
 script_cve_id("CVE-2004-0957", "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 script_bugtraq_id(12781);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-707 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in MySQL, a popular
database.  The Common Vulnerabilities and Exposures project identifies
the following problems:
    Sergei Golubchik discovered a problem in the access handling for
    similar named databases.  If a user is granted privileges to a
    database with a name containing an underscore ("_"), the user also
    gains privileges to other databases with similar names.
    Stefano Di Paola discovered that MySQL allows remote
    authenticated users with INSERT and DELETE privileges to execute
    arbitrary code by using CREATE FUNCTION to access libc calls.
    Stefano Di Paola discovered that MySQL allows remote authenticated
    users with INSERT and DELETE privileges to bypass library path
    restrictions and execute arbitrary libraries by using INSERT INTO
    to modify the mysql.func table.
   Stefano Di Paola discovered that MySQL uses predictable file names
   when creating temporary tables, which allows local users with
   CREATE TEMPORARY TABLE privileges to overwrite arbitrary files via
   a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-707');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA707] DSA-707-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-707-1 mysql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.11');
deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.11');
deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.11');
deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.11');
deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.11');
deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
