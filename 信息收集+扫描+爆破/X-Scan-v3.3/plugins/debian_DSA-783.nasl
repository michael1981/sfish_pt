# This script was automatically generated from the dsa-783
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19526);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "783");
 script_cve_id("CVE-2005-1636");
 script_bugtraq_id(13660);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-783 security update');
 script_set_attribute(attribute: 'description', value:
'Eric Romang discovered a temporary file vulnerability in a script
accompanied with MySQL, a popular database, that allows an attacker to
execute arbitrary SQL commands when the server is installed or
updated.
The old stable distribution (woody) as well as mysql-dfsg are not
affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.1.11a-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-783');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA783] DSA-783-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-783-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge1');
deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge1');
deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge1');
deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge1');
deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge1');
deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
