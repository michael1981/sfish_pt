# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-16.xml
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
 script_id(18380);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200505-16");
 script_cve_id("CVE-2005-1739");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-16
(ImageMagick, GraphicsMagick: Denial of Service vulnerability)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a
    Denial of Service vulnerability in the XWD decoder of ImageMagick and
    GraphicsMagick when setting a color mask to zero.
  
Impact

    A remote attacker could submit a specially crafted image to a user or
    an automated system making use of an affected utility, resulting in a
    Denial of Service by consumption of CPU time.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.2.2.3"
    All GraphicsMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/graphicsmagick-1.1.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1739');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-16] ImageMagick, GraphicsMagick: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick, GraphicsMagick: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.2.2.3"), vulnerable: make_list("lt 6.2.2.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/graphicsmagick", unaffected: make_list("ge 1.1.6-r1"), vulnerable: make_list("lt 1.1.6-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
