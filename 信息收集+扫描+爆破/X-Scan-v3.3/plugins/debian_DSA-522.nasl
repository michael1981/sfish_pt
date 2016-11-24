# This script was automatically generated from the dsa-522
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15359);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "522");
 script_cve_id("CVE-2004-0579");
 script_bugtraq_id(10575);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-522 security update');
 script_set_attribute(attribute: 'description', value:
'Max Vozeler discovered a format string vulnerability in super, a
program to allow specified users to execute commands with root
privileges.  This vulnerability could potentially be exploited by a
local user to execute arbitrary code with root privileges.
For the current stable distribution (woody), this problem has been
fixed in version 3.16.1-1.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-522');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-522
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA522] DSA-522-1 super");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-522-1 super");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'super', release: '3.0', reference: '3.16.1-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
