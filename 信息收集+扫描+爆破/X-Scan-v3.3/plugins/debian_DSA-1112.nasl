# This script was automatically generated from the dsa-1112
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22654);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1112");
 script_cve_id("CVE-2006-3081", "CVE-2006-3469");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1112 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in the MySQL database
server, which may lead to denial of service. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2006-3081
    "Kanatoko" discovered that the server can be crashed with feeding
    NULL values to the str_to_date() function.
CVE-2006-3469
    Jean-David Maillefer discovered that the server can be crashed with
    specially crafted date_format() function calls.
For the stable distribution (sarge) these problems have been fixed in
version 4.1.11a-4sarge5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1112');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql-dfsg-4.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1112] DSA-1112-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1112-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge5');
deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge5');
deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge5');
deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge5');
deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge5');
deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
