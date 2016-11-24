# This script was automatically generated from the dsa-1073
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22615);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1073");
 script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
 script_bugtraq_id(16850, 17780);
 script_xref(name: "CERT", value: "602457");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1073 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in MySQL, a popular SQL
database.  The Common Vulnerabilities and Exposures Project identifies
the following problems:
CVE-2006-0903
    Improper handling of SQL queries containing the NULL character
    allows local users to bypass logging mechanisms.
CVE-2006-1516
    Usernames without a trailing null byte allow remote attackers to
    read portions of memory.
CVE-2006-1517
    A request with an incorrect packet length allows remote attackers
    to obtain sensitive information.
CVE-2006-1518
    Specially crafted request packets with invalid length values allow
    the execution of arbitrary code.
The following vulnerability matrix shows which version of MySQL in
which distribution has this problem fixed:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1073');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1073] DSA-1073-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1073-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge3');
deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge3');
deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge3');
deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge3');
deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
