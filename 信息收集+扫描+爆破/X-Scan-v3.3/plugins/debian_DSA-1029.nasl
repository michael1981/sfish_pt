# This script was automatically generated from the dsa-1029
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22571);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1029");
 script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
 script_bugtraq_id(16187, 16364, 16720);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1029 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in libphp-adodb, the \'adodb\'
database abstraction layer for PHP.  The Common Vulnerabilities and
Exposures project identifies the following problems:
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
For the old stable distribution (woody) these problems have been fixed in
version 1.51-1.2.
For the stable distribution (sarge) these problems have been fixed in
version 4.52-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1029');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libphp-adodb package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1029] DSA-1029-1 libphp-adodb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1029-1 libphp-adodb");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libphp-adodb', release: '3.0', reference: '1.51-1.2');
deb_check(prefix: 'libphp-adodb', release: '3.1', reference: '4.52-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
