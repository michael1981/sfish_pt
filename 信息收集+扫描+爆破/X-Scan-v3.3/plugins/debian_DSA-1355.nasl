# This script was automatically generated from the dsa-1355
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25936);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1355");
 script_cve_id("CVE-2007-3387");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1355 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that an integer overflow in the xpdf PDF viewer may lead
to the execution of arbitrary code if a malformed PDF file is opened.
kpdf includes a copy of the xpdf code and required an update as well.
For the oldstable distribution (sarge) this problem has been fixed in
version 3.3.2-2sarge5.
For the stable distribution (etch) this problem has been fixed in
version 3.5.5-3etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1355');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kpdf packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1355] DSA-1355-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1355-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kamera', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kcoloredit', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kdegraphics', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kdegraphics-dev', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kdegraphics-kfile-plugins', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kdvi', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kfax', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kgamma', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kghostview', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kiconedit', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kmrml', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kolourpaint', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kooka', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kpdf', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kpovmodeler', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kruler', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'ksnapshot', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'ksvg', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kuickshow', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kview', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kviewshell', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'libkscan-dev', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'libkscan1', release: '3.1', reference: '3.3.2-2sarge5');
deb_check(prefix: 'kamera', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kcoloredit', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kdegraphics', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kdegraphics-dbg', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kdegraphics-dev', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kdegraphics-doc-html', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kdegraphics-kfile-plugins', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kdvi', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kfax', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kfaxview', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kgamma', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kghostview', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kiconedit', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kmrml', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kolourpaint', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kooka', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kpdf', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kpovmodeler', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kruler', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'ksnapshot', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'ksvg', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kuickshow', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kview', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'kviewshell', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'libkscan-dev', release: '4.0', reference: '3.5.5-3etch1');
deb_check(prefix: 'libkscan1', release: '4.0', reference: '3.5.5-3etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
