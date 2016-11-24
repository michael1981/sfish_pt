# This script was automatically generated from the dsa-756
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19196);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "756");
 script_cve_id("CVE-2005-1769", "CVE-2005-2095");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-756 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Martijn Brinkers discovered cross-site scripting vulnerabilities
    that allow remote attackers to inject arbitrary web script or HTML
    in the URL and e-mail messages.
    James Bercegay of GulfTech Security discovered a vulnerability in
    the variable handling which could lead to attackers altering other
    people\'s preferences and possibly reading them, writing files at
    any location writable for www-data and cross site scripting.
For the old stable distribution (woody) these problems have been fixed in
version 1.2.6-4.
For the stable distribution (sarge) these problems have been fixed in
version 1.4.4-6sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-756');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squirrelmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA756] DSA-756-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-756-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-4');
deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-6sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
