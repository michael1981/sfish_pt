# This script was automatically generated from the dsa-1752
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35993);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1752");
 script_cve_id("CVE-2009-0364");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1752 security update');
 script_set_attribute(attribute: 'description', value:
'Wilfried Goesgens discovered that WebCit, the web-based user interface
for the Citadel groupware system, contains a format string
vulnerability in the mini_calendar component, possibly allowing
arbitrary code execution (CVE-2009-0364).
For the stable distribution (lenny), this problem has been fixed in
version 7.37-dfsg-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1752');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your webcit packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1752] DSA-1752-1 webcit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1752-1 webcit");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'citadel-webcit', release: '5.0', reference: '7.37-dfsg-7');
deb_check(prefix: 'webcit', release: '5.0', reference: '7.37-dfsg-7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
