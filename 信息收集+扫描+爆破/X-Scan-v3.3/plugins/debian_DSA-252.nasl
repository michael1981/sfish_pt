# This script was automatically generated from the dsa-252
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15089);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "252");
 script_cve_id("CVE-2003-0056");
 script_bugtraq_id(6676);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-252 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in slocate, a secure locate replacement.
A buffer overflow in the setgid program slocate can be used to execute
arbitrary code as group slocate.  This can be used to alter the
slocate database.
For the stable distribution (woody) this problem has been
fixed in version 2.6-1.3.1.
The old stable distribution (potato) is not affected by this problem.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-252');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your slocate package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA252] DSA-252-1 slocate");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-252-1 slocate");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'slocate', release: '3.0', reference: '2.6-1.3.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
