# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(40519);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200908-03");
 script_cve_id("CVE-2009-2285", "CVE-2009-2347");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-03
(libTIFF: User-assisted execution of arbitrary code)


    Two vulnerabilities have been reported in libTIFF:
    wololo reported a buffer underflow in the LZWDecodeCompat() function
    (CVE-2009-2285).
    Tielei Wang of ICST-ERCIS, Peking University reported two integer
    overflows leading to heap-based buffer overflows in the tiff2rgba and
    rgb2ycbcr tools (CVE-2009-2347).
  
Impact

    A remote attacker could entice a user to open a specially crafted TIFF
    file with an application making use of libTIFF or the tiff2rgba and
    rgb2ycbcr tools, possibly resulting in the execution of arbitrary code
    with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libTIFF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.8.2-r8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2285');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2347');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-03] libTIFF: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libTIFF: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.8.2-r8"), vulnerable: make_list("lt 3.8.2-r8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
