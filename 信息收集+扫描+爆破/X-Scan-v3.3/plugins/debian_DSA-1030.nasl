# This script was automatically generated from the dsa-1030
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22572);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1030");
 script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
 script_bugtraq_id(16187, 16364, 16720);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1030 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in libphp-adodb, the
\'adodb\' database abstraction layer for PHP, which is embedded in
moodle, a course management system for online learning.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-0146
    Andreas Sandblad discovered that improper user input sanitisation
    results in a potential remote SQL injection vulnerability enabling
    an attacker to compromise applications, access or modify data, or
    exploit vulnerabilities in the underlying database implementation.
    This requires the MySQL root password to be empty.  It is fixed by
    limiting access to the script in question.
CVE-2006-0147
    A dynamic code evaluation vulnerability allows remote attackers to
    execute arbitrary PHP functions via the \'do\' parameter.
CVE-2006-0410
    Andy Staudacher discovered an SQL injection vulnerability due to
    insufficient input sanitising that allows remote attackers to
    execute arbitrary SQL commands.
CVE-2006-0806
    GulfTech Security Research discovered multiple cross-site
    scripting vulnerabilities due to improper user-supplied input
    sanitisation.  Attackers can exploit these vulnerabilities to
    cause arbitrary scripts to be executed in the browser of an
    unsuspecting user\'s machine, or result in the theft of
    cookie-based authentication credentials.
The old stable distribution (woody) does not contain moodle packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.4.4.dfsg.1-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1030');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your moodle package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1030] DSA-1030-1 moodle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1030-1 moodle");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'moodle', release: '3.1', reference: '1.4.4.dfsg.1-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
