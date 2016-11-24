# This script was automatically generated from the dsa-1824
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39569);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1824");
 script_cve_id("CVE-2009-1150", "CVE-2009-1151");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1824 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in phpMyAdmin, a tool
to administer MySQL over the web. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-1150
  Cross site scripting vulnerability in the export page allow for an
  attacker that can place crafted cookies with the user to inject
  arbitrary web script or HTML.
CVE-2009-1151
  Static code injection allows for a remote attacker to inject arbitrary
  code into phpMyAdmin via the setup.php script. This script is in Debian
  under normal circumstances protected via Apache authentication.
  However, because of a recent worm based on this exploit, we are patching
  it regardless, to also protect installations that somehow still expose
  the setup.php script.
For the old stable distribution (etch), these problems have been fixed in
version 2.9.1.1-11.
For the stable distribution (lenny), these problems have been fixed in
version 2.11.8.1-5+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1824');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1824] DSA-1824-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1824-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '4.0', reference: '2.9.1.1-11');
deb_check(prefix: 'phpmyadmin', release: '5.0', reference: '2.11.8.1-5+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
