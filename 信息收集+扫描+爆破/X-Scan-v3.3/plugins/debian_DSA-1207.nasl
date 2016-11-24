# This script was automatically generated from the dsa-1207
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23656);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1207");
 script_cve_id("CVE-2005-3621", "CVE-2005-3665", "CVE-2006-1678", "CVE-2006-2418", "CVE-2006-5116");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1207 security update');
 script_set_attribute(attribute: 'description', value:
'The phpmyadmin update in DSA 1207 introduced a regression. This update
corrects this flaw. For completeness, please find below the original
advisory text:
Several remote vulnerabilities have been discovered in phpMyAdmin, a
program to administrate MySQL over the web. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2005-3621
    CRLF injection vulnerability allows remote attackers to conduct
    HTTP response splitting attacks.
CVE-2005-3665
    Multiple cross-site scripting (XSS) vulnerabilities allow remote
    attackers to inject arbitrary web script or HTML via the (1) HTTP_HOST
    variable and (2) various scripts in the libraries directory that
    handle header generation.
CVE-2006-1678
    Multiple cross-site scripting (XSS) vulnerabilities allow remote
    attackers to inject arbitrary web script or HTML via scripts in the
    themes directory.
CVE-2006-2418
    A cross-site scripting (XSS) vulnerability allows remote attackers
    to inject arbitrary web script or HTML via the db parameter of
    footer.inc.php.
CVE-2006-5116
    A remote attacker could overwrite internal variables through the
    _FILES global variable.
For the stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1207');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1207] DSA-1207-2 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1207-2 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '3.1', reference: '2.6.2-3sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
