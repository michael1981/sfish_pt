# This script was automatically generated from the dsa-1210
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23659);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1210");
 script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4571");
 script_bugtraq_id(20042);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1210 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Firefox.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
CVE-2006-2788
    Fernando Ribeiro discovered that a vulnerability in the getRawDER
    function allows remote attackers to cause a denial of service
    (hang) and possibly execute arbitrary code.
CVE-2006-4340
    Daniel Bleichenbacher recently described an implementation error
    in RSA signature verification that cause the application to
    incorrectly trust SSL certificates.
    Priit Laes reported that a JavaScript regular expression can
    trigger a heap-based buffer overflow which allows remote attackers
    to cause a denial of service and possibly execute arbitrary code.
CVE-2006-4568
    A vulnerability has been discovered that allows remote attackers
    to bypass the security model and inject content into the sub-frame
    of another site.
CVE-2006-4571
    Multiple unspecified vulnerabilities in Firefox, Thunderbird and
    SeaMonkey allow remote attackers to cause a denial of service,
    corrupt memory, and possibly execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge12.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1210');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Firefox packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1210] DSA-1210-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1210-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge12');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge12');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge12');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
