# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-28.xml
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
 script_id(35929);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-28");
 script_cve_id("CVE-2008-5907", "CVE-2008-6218", "CVE-2009-0040");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-28
(libpng: Multiple vulnerabilities)


    Multiple vulnerabilities were discovered in libpng:
    A
    memory leak bug was reported in png_handle_tEXt(), a function that is
    used while reading PNG images (CVE-2008-6218).
    A memory
    overwrite bug was reported by Jon Foster in png_check_keyword(), caused
    by writing overlong keywords to a PNG file (CVE-2008-5907).
    A
    memory corruption issue, caused by an incorrect handling of an out of
    memory condition has been reported by Tavis Ormandy of the Google
    Security Team. That vulnerability affects direct uses of
    png_read_png(), pCAL chunk and 16-bit gamma table handling
    (CVE-2009-0040).
  
Impact

    A remote attacker may execute arbitrary code with the privileges of the
    user opening a specially crafted PNG file by exploiting the erroneous
    out-of-memory handling. An attacker may also exploit the
    png_check_keyword() error to set arbitrary memory locations to 0, if
    the application allows overlong, user-controlled keywords when writing
    PNG files. The png_handle_tEXT() vulnerability may be exploited by an
    attacker to potentially consume all memory on a users system when a
    specially crafted PNG file is opened.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libpng-1.2.35"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5907');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6218');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0040');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-28] libpng: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpng: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libpng", unaffected: make_list("ge 1.2.35"), vulnerable: make_list("lt 1.2.35")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
