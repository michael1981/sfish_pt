# This script was automatically generated from the dsa-675
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16365);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "675");
 script_cve_id("CVE-2005-0019");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-675 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjölund discovered that hztty, a converter for GB, Big5 and zW/HZ
Chinese encodings in a tty session, can be triggered to execute
arbitrary commands with group utmp privileges.
For the stable distribution (woody) this problem has been fixed in
version 2.0-5.2woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-675');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hztty package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA675] DSA-675-1 hztty");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-675-1 hztty");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hztty', release: '3.0', reference: '2.0-5.2woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
