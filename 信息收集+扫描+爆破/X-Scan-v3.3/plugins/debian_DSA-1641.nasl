# This script was automatically generated from the dsa-1641
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34254);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1641");
 script_cve_id("CVE-2008-3197", "CVE-2008-3456", "CVE-2008-3457", "CVE-2008-4096");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1641 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in phpMyAdmin, a
tool to administrate MySQL databases over the web. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-4096
    Remote authenticated users could execute arbitrary code on the
    host running phpMyAdmin through manipulation of a script parameter.
CVE-2008-3457
    Cross site scripting through the setup script was possible in
    rare circumstances.
CVE-2008-3456
    Protection has been added against remote websites loading phpMyAdmin
    into a frameset.
CVE-2008-3197
    Cross site request forgery allowed remote attackers to create a new
    database, but not perform any other action on it.
For the stable distribution (etch), these problems have been fixed in
version 4:2.9.1.1-8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1641');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1641] DSA-1641-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1641-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '4.0', reference: '2.9.1.1-8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
