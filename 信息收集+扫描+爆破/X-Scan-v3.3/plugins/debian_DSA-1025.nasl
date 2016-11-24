# This script was automatically generated from the dsa-1025
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22567);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "1025");
 script_bugtraq_id(17310);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1025 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" discovered three buffer overflow errors in the xfig
import code of dia, a diagram editor, that can lead to the execution
of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 0.88.1-3woody1.
For the stable distribution (sarge) these problems have been fixed in
version 0.94.0-7sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1025');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dia package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1025] DSA-1025-1 dia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2006-1550");
 script_summary(english: "DSA-1025-1 dia");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dia', release: '3.0', reference: '0.88.1-3woody1');
deb_check(prefix: 'dia-common', release: '3.0', reference: '0.88.1-3woody1');
deb_check(prefix: 'dia-gnome', release: '3.0', reference: '0.88.1-3woody1');
deb_check(prefix: 'dia', release: '3.1', reference: '0.94.0-7sarge3');
deb_check(prefix: 'dia-common', release: '3.1', reference: '0.94.0-7sarge3');
deb_check(prefix: 'dia-gnome', release: '3.1', reference: '0.94.0-7sarge3');
deb_check(prefix: 'dia-libs', release: '3.1', reference: '0.94.0-7sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
