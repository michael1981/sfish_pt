# This script was automatically generated from the dsa-1431
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29339);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1431");
 script_cve_id("CVE-2007-6183");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1431 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that ruby-gnome2, the GNOME-related bindings for the Ruby
language, didn\'t properly sanitize input prior to constructing dialogs.
This could allow the execution of arbitrary code if untrusted input
is displayed within a dialog.
For the old stable distribution (sarge), this problem has been fixed in
version 0.12.0-2sarge1.
For the stable distribution (etch), this problem has been fixed in version
0.15.0-1.1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1431');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ruby-gnome2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1431] DSA-1431-1 ruby-gnome2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1431-1 ruby-gnome2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libart2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libatk1-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgconf2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgda2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgdk-pixbuf2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libglade2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libglib2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgnome2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgnomecanvas2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgnomeprint2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgnomeprintui2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgnomevfs2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgstreamer0.8-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgtk2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgtkglext1-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgtkhtml2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libgtksourceview1-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libpanel-applet2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libpango1-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'librsvg2-ruby', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'ruby-gnome2', release: '3.1', reference: '0.12.0-2sarge1');
deb_check(prefix: 'libart2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libatk1-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgconf2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgda2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgdk-pixbuf2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libglade2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libglib2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgnome2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgnomecanvas2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgnomeprint2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgnomeprintui2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgnomevfs2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgstreamer0.8-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgtk-mozembed-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgtk2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgtkglext1-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgtkhtml2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libgtksourceview1-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libpanel-applet2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libpango1-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'librsvg2-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'libvte-ruby', release: '4.0', reference: '0.15.0-1.1etch1');
deb_check(prefix: 'ruby-gnome2', release: '4.0', reference: '0.15.0-1.1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
