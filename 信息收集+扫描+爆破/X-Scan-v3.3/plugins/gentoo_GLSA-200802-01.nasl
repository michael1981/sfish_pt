# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-01.xml
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
 script_id(30243);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200802-01");
 script_cve_id("CVE-2007-6697", "CVE-2008-0544");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-01
(SDL_image: Two buffer overflow vulnerabilities)


    The LWZReadByte() function in file IMG_gif.c and the IMG_LoadLBM_RW()
    function in file IMG_lbm.c each contain a boundary error that can be
    triggered to cause a static buffer overflow and a heap-based buffer
    overflow. The first boundary error comes from some old vulnerable GD
    PHP code (CVE-2006-4484).
  
Impact

    A remote attacker can make an application using the SDL_image library
    to process a specially crafted GIF file or IFF ILBM file that will
    trigger a buffer overflow, resulting in the execution of arbitrary code
    with the permissions of the application or the application crash.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SDL_image users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/sdl-image-1.2.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/28640/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6697');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0544');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-01] SDL_image: Two buffer overflow vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SDL_image: Two buffer overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/sdl-image", unaffected: make_list("ge 1.2.6-r1"), vulnerable: make_list("lt 1.2.6-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
