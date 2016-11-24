# This script was automatically generated from the dsa-1370
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26031);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1370");
 script_cve_id("CVE-2006-6942", "CVE-2006-6944", "CVE-2007-1325", "CVE-2007-1395", "CVE-2007-2245");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1370 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in phpMyAdmin, a
program to administrate MySQL over the web. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2007-1325
    The PMA_ArrayWalkRecursive function in libraries/common.lib.php
    does not limit recursion on arrays provided by users, which allows
    context-dependent attackers to cause a denial of service (web
    server crash) via an array with many dimensions.
    This issue affects only the stable distribution (Etch).
CVE-2007-1395
    Incomplete blacklist vulnerability in index.php allows remote
    attackers to conduct cross-site scripting (XSS) attacks by
    injecting arbitrary JavaScript or HTML in a (1) db or (2) table
    parameter value followed by an uppercase </SCRIPT> end tag,
    which bypasses the protection against lowercase </script>.
    This issue affects only the stable distribution (Etch).
CVE-2007-2245
    Multiple cross-site scripting (XSS) vulnerabilities allow remote
    attackers to inject arbitrary web script or HTML via (1) the
    fieldkey parameter to browse_foreigners.php or (2) certain input
    to the PMA_sanitize function.
CVE-2006-6942
    Multiple cross-site scripting (XSS) vulnerabilities allow remote
    attackers to inject arbitrary HTML or web script via (1) a comment
    for a table name, as exploited through (a) db_operations.php,
    (2) the db parameter to (b) db_create.php, (3) the newname parameter
    to db_operations.php, the (4) query_history_latest,
    (5) query_history_latest_db, and (6) querydisplay_tab parameters to
    (c) querywindow.php, and (7) the pos parameter to (d) sql.php.
    This issue affects only the oldstable distribution (Sarge).
CVE-2006-6944
    phpMyAdmin allows remote attackers to bypass Allow/Deny access rules
    that use IP addresses via false headers.
    This issue affects only the oldstable distribution (Sarge).
For the old stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge5.
For the stable distribution (etch) these problems have been fixed in
version 2.9.1.1-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1370');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1370] DSA-1370-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1370-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '3.1', reference: '2.6.2-3sarge5');
deb_check(prefix: 'phpmyadmin', release: '4.0', reference: '2.9.1.1-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
