# This script was automatically generated from the dsa-546
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15383);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "546");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0788");
 script_xref(name: "CERT", value: "577654");
 script_xref(name: "CERT", value: "729894");
 script_xref(name: "CERT", value: "825374");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-546 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered several problems in gdk-pixbuf, the GdkPixBuf
library used in Gtk.  It is possible for an attacker to execute
arbitrary code on the victims machine.  Gdk-pixbuf for Gtk+1.2 is an
external package.  For Gtk+2.0 it\'s part of the main gtk package.
The Common Vulnerabilities and Exposures Project identifies the
following vulnerabilities:
    Denial of service in bmp loader.
    Heap-based overflow in pixbuf_create_from_xpm.
    Integer overflow in the ico loader.
For the stable distribution (woody) these problems have been fixed in
version 0.17.0-2woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-546');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gdk-pixbuf packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA546] DSA-546-1 gdk-pixbuf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-546-1 gdk-pixbuf");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libgdk-pixbuf-dev', release: '3.0', reference: '0.17.0-2woody2');
deb_check(prefix: 'libgdk-pixbuf-gnome-dev', release: '3.0', reference: '0.17.0-2woody2');
deb_check(prefix: 'libgdk-pixbuf-gnome2', release: '3.0', reference: '0.17.0-2woody2');
deb_check(prefix: 'libgdk-pixbuf2', release: '3.0', reference: '0.17.0-2woody2');
deb_check(prefix: 'gdk-pixbuf', release: '3.0', reference: '0.17.0-2woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
