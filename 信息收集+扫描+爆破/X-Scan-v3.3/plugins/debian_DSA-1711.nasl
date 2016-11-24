# This script was automatically generated from the dsa-1711
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35463);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1711");
 script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
 script_bugtraq_id(33376);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1711 security update');
 script_set_attribute(attribute: 'description', value:
'Several remotely exploitable vulnerabilities have been discovered in the
TYPO3 web content management framework.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2009-0255
    Chris John Riley discovered that the TYPO3-wide used encryption key is
    generated with an insufficiently random seed resulting in low entropy
    which makes it easier for attackers to crack this key.
CVE-2009-0256
    Marcus Krause discovered that TYPO3 is not invalidating a supplied session
    on authentication which allows an attacker to take over a victims
    session via a session fixation attack.
CVE-2009-0257
    Multiple cross-site scripting vulnerabilities allow remote attackers to
    inject arbitrary web script or HTML via various arguments and user supplied
    strings used in the indexed search system extension, adodb extension test
    scripts or the workspace module.
CVE-2009-0258
    Mads Olesen discovered a remote command injection vulnerability in
    the indexed search system extension which allows attackers to
    execute arbitrary code via a crafted file name which is passed
    unescaped to various system tools that extract file content for
    the indexing.
Because of CVE-2009-0255, please make sure that besides installing
this update, you also create a new encryption key after the
installation.
For the stable distribution (etch) these problems have been fixed in
version 4.0.2+debian-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1711');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your TYPO3 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1711] DSA-1711-1 typo3-src");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1711-1 typo3-src");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'typo3', release: '4.0', reference: '4.0.2+debian-7');
deb_check(prefix: 'typo3-src-4.0', release: '4.0', reference: '4.0.2+debian-7');
deb_check(prefix: 'typo3-src', release: '4.0', reference: '4.0.2+debian-7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
