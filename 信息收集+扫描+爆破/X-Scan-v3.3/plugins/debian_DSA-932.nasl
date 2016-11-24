# This script was automatically generated from the dsa-932
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22798);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "932");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-932 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf, the Portable Document Format (PDF) suite, that can
lead to a denial of service by crashing the application or possibly to
the execution of arbitrary code.  The same code is present in kpdf
which is part of the kdegraphics package.
The old stable distribution (woody) does not contain kpdf packages.
For the stable distribution (sarge) these problems have been fixed in
version 3.3.2-2sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-932');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kpdf package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA932] DSA-932-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-932-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kamera', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kcoloredit', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kdegraphics', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kdegraphics-dev', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kdegraphics-kfile-plugins', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kdvi', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kfax', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kgamma', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kghostview', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kiconedit', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kmrml', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kolourpaint', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kooka', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kpdf', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kpovmodeler', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kruler', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'ksnapshot', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'ksvg', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kuickshow', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kview', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'kviewshell', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'libkscan-dev', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'libkscan1', release: '3.1', reference: '3.3.2-2sarge3');
deb_check(prefix: 'xpdf', release: '3.1', reference: '3.3.2-2sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
