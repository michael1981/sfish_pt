# This script was automatically generated from the dsa-1007
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22549);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1007");
 script_cve_id("CVE-2006-1225", "CVE-2006-1226", "CVE-2006-1227", "CVE-2006-1228");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1007 security update');
 script_set_attribute(attribute: 'description', value:
'The Drupal Security Team discovered several vulnerabilities in Drupal,
a fully-featured content management and discussion engine.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-1225
    Due to missing input sanitising a remote attacker could inject
    headers of outgoing e-mail messages and use Drupal as a spam
    proxy.
CVE-2006-1226
    Missing input sanity checks allows attackers to inject arbitrary
    web script or HTML.
CVE-2006-1227
    Menu items created with the menu.module lacked access control,
    which might allow remote attackers to access administrator pages.
CVE-2006-1228
    Markus Petrux discovered a bug in the session fixation which may
    allow remote attackers to gain Drupal user privileges.
The old stable distribution (woody) does not contain Drupal packages.
For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1007');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1007] DSA-1007-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1007-1 drupal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
