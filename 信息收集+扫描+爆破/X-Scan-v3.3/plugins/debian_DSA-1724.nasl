# This script was automatically generated from the dsa-1724
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35691);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1724");
 script_cve_id("CVE-2008-5153", "CVE-2009-0500", "CVE-2009-0502");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1724 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Moodle, an online
course management system.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-0500
    It was discovered that the information stored in the log tables
    was not properly sanitized, which could allow attackers to inject
    arbitrary web code.
CVE-2009-0502
    It was discovered that certain input via the "Login as" function
    was not properly sanitised leading to the injection of arbitrary
    web script.
CVE-2008-5153
    Dmitry E. Oboukhov discovered that the SpellCheker plugin creates
    temporary files insecurely, allowing a denial of service attack.
    Since the plugin was unused, it is removed in this update.
For the stable distribution (etch) these problems have been fixed in
version 1.6.3-2+etch2.
For the testing (lenny) distribution these problems have been fixed in
version 1.8.2.dfsg-3+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1724');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your moodle package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1724] DSA-1724-1 moodle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1724-1 moodle");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'moodle', release: '4.0', reference: '1.6.3-2+etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
