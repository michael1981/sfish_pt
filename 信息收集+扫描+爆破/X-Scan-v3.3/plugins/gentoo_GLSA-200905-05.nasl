# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-05.xml
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
 script_id(38886);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200905-05");
 script_cve_id("CVE-2009-0946");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-05
(FreeType: Multiple vulnerabilities)


    Tavis Ormandy reported multiple integer overflows in the
    cff_charset_compute_cids() function in cff/cffload.c, sfnt/tccmap.c and
    the ft_smooth_render_generic() function in smooth/ftsmooth.c, possibly
    leading to heap or stack-based buffer overflows.
  
Impact

    A remote attacker could entice a user or automated system to open a
    specially crafted font file, possibly resulting in the execution of
    arbitrary code with the privileges of the user running the application,
    or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FreeType users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/freetype-2.3.9-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0946');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-05] FreeType: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeType: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/freetype", unaffected: make_list("ge 2.3.9-r1", "lt 2.0"), vulnerable: make_list("lt 2.3.9-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
