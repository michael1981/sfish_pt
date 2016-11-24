# This script was automatically generated from the dsa-296
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15133);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "296");
 script_cve_id("CVE-2003-0204");
 script_bugtraq_id(7318);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-296 security update');
 script_set_attribute(attribute: 'description', value:
'The KDE team discovered a vulnerability in the way KDE uses Ghostscript
software for processing of PostScript (PS) and PDF files.  An attacker
could provide a malicious PostScript or PDF file via mail or websites
that could lead to executing arbitrary commands under the privileges
of the user viewing the file or when the browser generates a directory
listing with thumbnails.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.4 of kdebase and associated packages.
The old stable distribution (potato) is not affected since it does not
contain KDE.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-296');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdebase and associated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA296] DSA-296-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-296-1 kdebase");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kate', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdebase-audiolibs', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdebase-dev', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdebase-doc', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdebase-libs', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdewallpapers', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kdm', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'konqueror', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'konsole', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'kscreensaver', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'libkonq-dev', release: '3.0', reference: '2.2.2-14.4');
deb_check(prefix: 'libkonq3', release: '3.0', reference: '2.2.2-14.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
