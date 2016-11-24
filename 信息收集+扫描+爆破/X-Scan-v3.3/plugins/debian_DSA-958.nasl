# This script was automatically generated from the dsa-958
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22824);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "958");
 script_cve_id("CVE-2005-3973", "CVE-2005-3974", "CVE-2005-3975");
 script_bugtraq_id(15663, 15674, 15677);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-958 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in drupal, a
fully-featured content management/discussion engine.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
CVE-2005-3973
    Several cross-site scripting vulnerabilities allow remote
    attackers to inject arbitrary web script or HTML.
CVE-2005-3974
    When running on PHP5, Drupal does not correctly enforce user
    privileges, which allows remote attackers to bypass the "access
    user profiles" permission.
CVE-2005-3975
    An interpretation conflict allows remote authenticated users to
    inject arbitrary web script or HTML via HTML in a file with a GIF
    or JPEG file extension.
The old stable distribution (woody) does not contain drupal packages.
For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-958');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA958] DSA-958-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-958-1 drupal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
