# This script was automatically generated from the dsa-461
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15298);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "461");
 script_cve_id("CVE-2004-0188");
 script_bugtraq_id(9756);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-461 security update');
 script_set_attribute(attribute: 'description', value:
'Leon Juranic discovered a buffer overflow related to the
getpass(3) library function in
calife, a program which provides super user privileges to specific
users.  A local attacker could potentially
exploit this vulnerability, given knowledge of a local user\'s password
and the presence of at least one entry in /etc/calife.auth, to execute
arbitrary code with root privileges.
For the current stable distribution (woody) this problem has been
fixed in version 2.8.4c-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-461');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-461
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA461] DSA-461-1 calife");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-461-1 calife");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'calife', release: '3.0', reference: '2.8.4c-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
