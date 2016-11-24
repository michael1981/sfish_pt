# This script was automatically generated from the dsa-464
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15301);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "464");
 script_cve_id("CVE-2004-0111");
 script_bugtraq_id(9842);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-464 security update');
 script_set_attribute(attribute: 'description', value:
'Thomas Kristensen discovered a vulnerability in gdk-pixbuf (binary
package libgdk-pixbuf2), the GdkPixBuf image library for Gtk, that can
cause the surrounding application to crash.  To exploit this problem,
a remote attacker could send a carefully-crafted BMP file via mail,
which would cause e.g. Evolution to crash but is probably not limited
to Evolution.
For the stable distribution (woody) this problem has been fixed in
version 0.17.0-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-464');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libgdk-pixbuf2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA464] DSA-464-1 gdk-pixbuf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-464-1 gdk-pixbuf");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libgdk-pixbuf-dev', release: '3.0', reference: '0.17.0-2woody1');
deb_check(prefix: 'libgdk-pixbuf-gnome-dev', release: '3.0', reference: '0.17.0-2woody1');
deb_check(prefix: 'libgdk-pixbuf-gnome2', release: '3.0', reference: '0.17.0-2woody1');
deb_check(prefix: 'libgdk-pixbuf2', release: '3.0', reference: '0.17.0-2woody1');
deb_check(prefix: 'gdk-pixbuf', release: '3.0', reference: '0.17.0-2woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
