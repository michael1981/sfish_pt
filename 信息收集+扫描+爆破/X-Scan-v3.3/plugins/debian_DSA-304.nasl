# This script was automatically generated from the dsa-304
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15141);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "304");
 script_cve_id("CVE-2003-0188");
 script_bugtraq_id(7613);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-304 security update');
 script_set_attribute(attribute: 'description', value:
'Leonard Stiles discovered that lv, a multilingual file viewer, would
read options from a configuration file in the current directory.
Because such a file could be placed there by a malicious user, and lv
configuration options can be used to execute commands, this
represented a security vulnerability.  An attacker could gain the
privileges of the user invoking lv, including root.
For the stable distribution (woody) this problem has been fixed in
version 4.49.4-7woody2.
For the old stable distribution (potato) this problem has been fixed
in version 4.49.3-4potato2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-304');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-304
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA304] DSA-304-1 lv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-304-1 lv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lv', release: '2.2', reference: '4.49.3-4potato2');
deb_check(prefix: 'lv', release: '3.0', reference: '4.49.4-7woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
