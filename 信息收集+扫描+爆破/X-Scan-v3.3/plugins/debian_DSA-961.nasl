# This script was automatically generated from the dsa-961
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22827);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "961");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-961 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf which are also present in pdfkit.framework, the
GNUstep framework for rendering PDF content, and which can lead to a
denial of service by crashing the application or possibly to the
execution of arbitrary code.
The old stable distribution (woody) does not contain pdfkit.framework
packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.8-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-961');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pdfkit.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA961] DSA-961-1 pdfkit.framework");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-961-1 pdfkit.framework");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
