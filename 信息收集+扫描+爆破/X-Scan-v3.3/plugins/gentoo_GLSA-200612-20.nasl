# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-20.xml
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
 script_id(23957);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-20");
 script_cve_id("CVE-2006-4806", "CVE-2006-4807", "CVE-2006-4808", "CVE-2006-4809");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-20
(imlib2: Multiple vulnerabilities)


    M. Joonas Pihlaja discovered several buffer overflows in loader_argb.c,
    loader_png.c, loader_lbm.c, loader_jpeg.c, loader_tiff.c, loader_tga.c,
    loader_pnm.c and an out-of-bounds memory read access in loader_tga.c.
  
Impact

    An attacker can entice a user to process a specially crafted JPG, ARGB,
    PNG, LBM, PNM, TIFF, or TGA image with an "imlib2*" binary or another
    application using the imlib2 libraries. Successful exploitation of the
    buffer overflows causes the execution of arbitrary code with the
    permissions of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All imlib2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/imlib2-1.3.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4806');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4807');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4808');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4809');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-20] imlib2: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'imlib2: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/imlib2", unaffected: make_list("ge 1.3.0"), vulnerable: make_list("lt 1.3.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
