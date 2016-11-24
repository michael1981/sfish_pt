# This script was automatically generated from the dsa-788
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19531);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "788");
 script_cve_id("CVE-2005-2626", "CVE-2005-2627");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-788 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in kismet, a
wireless 802.11b monitoring tool.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Insecure handling of unprintable characters in the SSID.
    Multiple integer underflows could allow remote attackers to
    execute arbitrary code.
The old stable distribution (woody) does not seem to be affected by
these problems.
For the stable distribution (sarge) these problems have been fixed in
version 2005.04.R1-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-788');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kismet package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA788] DSA-788-1 kismet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-788-1 kismet");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kismet', release: '3.1', reference: '2005.04.R1-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
