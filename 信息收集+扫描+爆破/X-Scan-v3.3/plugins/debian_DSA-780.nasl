# This script was automatically generated from the dsa-780
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19477);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "780");
 script_cve_id("CVE-2005-2097");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-780 security update');
 script_set_attribute(attribute: 'description', value:
'A bug has been discovered in the font handling code in xpdf, which is
also present in kpdf, the PDF viewer for KDE.  A specially crafted PDF
file could cause infinite resource consumption, in terms of both CPU
and disk space.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-780');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kpdf package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA780] DSA-780-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-780-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kamera', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kcoloredit', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kdegraphics', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kdegraphics-dev', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kdegraphics-kfile-plugins', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kdvi', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kfax', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kgamma', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kghostview', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kiconedit', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kmrml', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kolourpaint', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kooka', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kpdf', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kpovmodeler', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kruler', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'ksnapshot', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'ksvg', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kuickshow', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kview', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'kviewshell', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'libkscan-dev', release: '3.1', reference: '3.3.2-2sarge1');
deb_check(prefix: 'libkscan1', release: '3.1', reference: '3.3.2-2sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
