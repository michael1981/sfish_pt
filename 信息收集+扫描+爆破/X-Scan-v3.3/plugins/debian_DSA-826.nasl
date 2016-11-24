# This script was automatically generated from the dsa-826
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19795);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "826");
 script_cve_id("CVE-2005-1766", "CVE-2005-2710");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-826 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple security vulnerabilities have been identified in the
helix-player media player that could allow an attacker to execute code
on the victim\'s machine via specially crafted network resources.
        Buffer overflow in the RealText parser could allow remote code
        execution via a specially crafted RealMedia file with a long
        RealText string.
        Format string vulnerability in Real HelixPlayer and RealPlayer 10
        allows remote attackers to execute arbitrary code via the image
        handle attribute in a RealPix (.rp) or RealText (.rt) file.
For the stable distribution (sarge), these problems have been fixed in
version 1.0.4-1sarge1
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-826');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your helix-player package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA826] DSA-826-1 helix-player");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-826-1 helix-player");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'helix-player', release: '3.1', reference: '1.0.4-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
