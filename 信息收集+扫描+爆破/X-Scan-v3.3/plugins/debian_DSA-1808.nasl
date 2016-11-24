# This script was automatically generated from the dsa-1808
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38980);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1808");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1808 security update');
 script_set_attribute(attribute: 'description', value:
'Markus Petrux discovered a cross-site scripting vulnerability in the
taxonomy module of drupal6, a fully-featured content management
framework. It is also possible that certain browsers using the UTF-7
encoding are vulnerable to a different cross-site scripting
vulnerability.
For the stable distribution (lenny), these problems have been fixed in
version 6.6-3lenny2.
The oldstable distribution (etch) does not contain drupal6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1808');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal6 packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1808] DSA-1808-1 drupal6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1808-1 drupal6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal6', release: '5.0', reference: '6.6-3lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
