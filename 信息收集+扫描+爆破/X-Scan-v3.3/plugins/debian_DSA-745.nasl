# This script was automatically generated from the dsa-745
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18655);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "745");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-745 security update');
 script_set_attribute(attribute: 'description', value:
'Two input validation errors were discovered in drupal and its bundled
xmlrpc module. These errors can lead to the execution of arbitrary
commands on the web server running drupal.
drupal was not included in the old stable distribution (woody).
For the current stable distribution (sarge), these problems have been
fixed in version 4.5.3-3. 
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-745');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA745] DSA-745-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-1921", "CVE-2005-2106");
 script_summary(english: "DSA-745-1 drupal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
