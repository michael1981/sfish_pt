# This script was automatically generated from the dsa-320
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15157);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "320");
 script_cve_id("CVE-2003-0427");
 script_bugtraq_id(7914);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-320 security update');
 script_set_attribute(attribute: 'description', value:
'Ingo Saitz discovered a bug in mikmod whereby a long filename inside
an archive file can overflow a buffer when the archive is being read
by mikmod.
For the stable distribution (woody) this problem has been fixed in
version 3.1.6-4woody3.
For old stable distribution (potato) this problem has been fixed in
version 3.1.6-2potato3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-320');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-320
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA320] DSA-320-1 mikmod");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-320-1 mikmod");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mikmod', release: '2.2', reference: '3.1.6-2potato3');
deb_check(prefix: 'mikmod', release: '3.0', reference: '3.1.6-4woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
