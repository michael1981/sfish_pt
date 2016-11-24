# This script was automatically generated from the dsa-483
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15320);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "483");
 script_cve_id("CVE-2004-0381", "CVE-2004-0388");
 script_bugtraq_id(10142, 9976);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-483 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in mysql, a common database
system.  Two scripts contained in the package don\'t create temporary
files in a secure fashion.  This could allow a local attacker to
overwrite files with the privileges of the user invoking the MySQL
server, which is often the root user.  The Common Vulnerabilities and
Exposures identifies the following problems:
    The script mysqlbug in MySQL allows local users to overwrite
    arbitrary files via a symlink attack.
    The script mysqld_multi in MySQL allows local users to overwrite
    arbitrary files via a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-483');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql, mysql-dfsg and related
packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA483] DSA-483-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-483-1 mysql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.6');
deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.6');
deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.6');
deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.6');
deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.6');
deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.6');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
