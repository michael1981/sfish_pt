# This script was automatically generated from the dsa-1125
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22667);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1125");
 script_cve_id("CVE-2006-2742", "CVE-2006-2743", "CVE-2006-2831", "CVE-2006-2832", "CVE-2006-2833");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1125 security update');
 script_set_attribute(attribute: 'description', value:
'The Drupal update in DSA 1125 contained a regression. This update corrects
this flaw. For completeness, the original advisory text below:
Several remote vulnerabilities have been discovered in the Drupal web site
platform, which may lead to the execution of arbitrary web script. The
Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-2742
    A SQL injection vulnerability has been discovered in the "count" and
    "from" variables of the database interface.
CVE-2006-2743
    Multiple file extensions were handled incorrectly if Drupal ran on
    Apache with mod_mime enabled.
CVE-2006-2831
    A variation of CVE-2006-2743 was addressed as well.
CVE-2006-2832
    A Cross-Site-Scripting vulnerability in the upload module has been
    discovered.
CVE-2006-2833
    A Cross-Site-Scripting vulnerability in the taxonomy module has been
    discovered.
For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-6.1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1125');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1125] DSA-1125-2 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1125-2 drupal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-6.1sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
