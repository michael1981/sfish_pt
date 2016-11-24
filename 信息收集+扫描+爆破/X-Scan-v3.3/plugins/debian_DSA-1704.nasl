# This script was automatically generated from the dsa-1704
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35378);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1704");
 script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1704 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2008-5500
   Jesse Ruderman  discovered that the layout engine is vulnerable to
   DoS attacks that might trigger memory corruption and an integer
   overflow. (MFSA 2008-60)
CVE-2008-5503
   Boris Zbarsky discovered that an information disclosure attack could
   be performed via XBL bindings. (MFSA 2008-61)
CVE-2008-5506
   Marius Schilder discovered that it is possible to obtain sensible
   data via a XMLHttpRequest. (MFSA 2008-64)
CVE-2008-5507
   Chris Evans discovered that it is possible to obtain sensible data
   via a JavaScript URL. (MFSA 2008-65)
CVE-2008-5508
   Chip Salzenberg discovered possible phishing attacks via URLs with
   leading whitespaces or control characters. (MFSA 2008-66)
CVE-2008-5511
   It was discovered that it is possible to perform cross-site scripting
   attacks via an XBL binding to an "unloaded document." (MFSA 2008-68)
CVE-2008-5512
   It was discovered that it is possible to run arbitrary JavaScript
   with chrome privileges via unknown vectors. (MFSA 2008-68)
For the stable distribution (etch) these problems have been fixed in
version 1.8.0.15~pre080614i-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1704');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1704] DSA-1704-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1704-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
