# This script was automatically generated from the dsa-598
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15831);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "598");
 script_cve_id("CVE-2004-0987");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-598 security update');
 script_set_attribute(attribute: 'description', value:
'Max Vozeler noticed that yardradius, the YARD radius authentication
and accounting server, contained a stack overflow similar to the one
from radiusd which is referenced as CVE-2001-0534.  This could lead to
the execution of arbitrary code as root.
For the stable distribution (woody) this problem has been fixed in
version 1.0.20-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-598');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your yardradius package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA598] DSA-598-1 yardradius");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-598-1 yardradius");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'yardradius', release: '3.0', reference: '1.0.20-2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
