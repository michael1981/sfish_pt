# This script was automatically generated from the dsa-1251
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24248);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1251");
 script_cve_id("CVE-2006-6678");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1251 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that netrik, a text mode WWW browser with vi like
keybindings, doesn\'t properly sanitize temporary filenames when editing
textareas which could allow attackers to execute arbitrary commands via
shell metacharacters.
For the stable distribution (sarge), this problem has been fixed in version
1.15.4-1sarge1.
For the upcoming stable distribution (etch) this problem has been fixed in
version 1.15.3-1.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1251');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your netrik package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1251] DSA-1251-1 netrick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1251-1 netrick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'netrik', release: '3.1', reference: '1.15.3-1sarge1');
deb_check(prefix: 'netrik', release: '4.0', reference: '1.15.3-1.1');
deb_check(prefix: 'netrik', release: '3.1', reference: '1.15.4-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
