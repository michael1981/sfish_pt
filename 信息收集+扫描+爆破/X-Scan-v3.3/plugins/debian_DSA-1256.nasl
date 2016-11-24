# This script was automatically generated from the dsa-1256
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24295);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1256");
 script_cve_id("CVE-2007-0010");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1256 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the image loading code in the GTK+ graphical user
interface library performs insufficient error handling when loading
malformed images, which may lead to denial of service.
For the stable distribution (sarge) this problem has been fixed in
version 2.6.4-3.2. This update lacks builds for the Motorola 680x0
architecture, which had build problems. Packages will be released once
this problem has been resolved.
For the upcoming stable distribution (etch) this problem has been
fixed in version 2.8.20-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1256');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your GTK packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1256] DSA-1256-1 gtk+2.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1256-1 gtk+2.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gtk2-engines-pixbuf', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'gtk2.0-examples', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'libgtk2.0-0', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'libgtk2.0-0-dbg', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'libgtk2.0-bin', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'libgtk2.0-common', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'libgtk2.0-dev', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'libgtk2.0-doc', release: '3.1', reference: '2.6.4-3.2');
deb_check(prefix: 'gtk+2.0', release: '4.0', reference: '2.8.20-5');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
