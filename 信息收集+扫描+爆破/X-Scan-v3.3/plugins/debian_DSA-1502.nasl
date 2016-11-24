# This script was automatically generated from the dsa-1502
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31146);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1502");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1502 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in wordpress, a weblog
manager. The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2007-3238
    Cross-site scripting (XSS) vulnerability in functions.php in the default 
    theme in WordPress allows remote authenticated administrators to inject 
    arbitrary web script or HTML via the PATH_INFO (REQUEST_URI) to 
    wp-admin/themes.php.
CVE-2007-2821
    SQL injection vulnerability in wp-admin/admin-ajax.php in WordPress 
    before 2.2 allows remote attackers to execute arbitrary SQL commands via 
    the cookie parameter.
CVE-2008-0193
    Cross-site scripting (XSS) vulnerability in wp-db-backup.php in 
    WordPress 2.0.11 and earlier allows remote attackers to inject 
    arbitrary web script or HTML via the backup parameter in a 
    wp-db-backup.php action to wp-admin/edit.php.
CVE-2008-0194
    Directory traversal vulnerability in wp-db-backup.php in WordPress 2.0.3 
    and earlier allows remote attackers to read arbitrary files, delete 
    arbitrary files, and cause a denial of service via a .. (dot dot) in the 
    backup parameter in a wp-db-backup.php action to wp-admin/edit.php.
Wordpress is not present in the oldstable distribution (sarge).
For the stable distribution (etch), these problems have been fixed in version
2.0.10-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1502');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wordpress package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1502] DSA-1502-1 wordpress");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1502-1 wordpress");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wordpress', release: '4.0', reference: '2.0.10-1etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
