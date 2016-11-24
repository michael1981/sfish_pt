# This script was automatically generated from the dsa-601
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15844);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "601");
 script_cve_id("CVE-2004-0941", "CVE-2004-0990");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-601 security update');
 script_set_attribute(attribute: 'description', value:
'More potential integer overflows have been found in the GD graphics
library which weren\'t covered by our security advisory 
DSA 589.  They
could be exploited by a specially crafted graphic and could lead to
the execution of arbitrary code on the victim\'s machine.
For the stable distribution (woody) these problems have been fixed in
version 1.8.4-17.woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-601');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libgd1 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA601] DSA-601-1 libgd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-601-1 libgd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libgd-dev', release: '3.0', reference: '1.8.4-17.woody4');
deb_check(prefix: 'libgd-noxpm-dev', release: '3.0', reference: '1.8.4-17.woody4');
deb_check(prefix: 'libgd1', release: '3.0', reference: '1.8.4-17.woody4');
deb_check(prefix: 'libgd1-noxpm', release: '3.0', reference: '1.8.4-17.woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
