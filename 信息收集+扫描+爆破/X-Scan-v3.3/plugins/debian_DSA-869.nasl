# This script was automatically generated from the dsa-869
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(20072);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "869");
 script_cve_id("CVE-2005-3068");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-869 security update');
 script_set_attribute(attribute: 'description', value:
'The developers of eric, a full featured Python IDE, have fixed a bug
in the processing of project files that could lead to the execution of
arbitrary code.
The old stable distribution (woody) does not contain an eric package.
For the stable distribution (sarge) this problem has been fixed in
version 3.6.2-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-869');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your eric package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA869] DSA-869-1 eric");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-869-1 eric");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'eric', release: '3.1', reference: '3.6.2-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
