# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-19.xml
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
 script_id(23727);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-19");
 script_cve_id("CVE-2006-5456");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-19
(ImageMagick: PALM and DCM buffer overflows)


    M. Joonas Pihlaja has reported that a boundary error exists within the
    ReadDCMImage() function of coders/dcm.c, causing the improper handling
    of DCM images. Pihlaja also reported that there are several boundary
    errors in the ReadPALMImage() function of coders/palm.c, similarly
    causing the improper handling of PALM images.
  
Impact

    An attacker could entice a user to open a specially crafted DCM or PALM
    image with ImageMagick, and possibly execute arbitrary code with the
    privileges of the user running ImageMagick.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.3.0.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5456');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-19] ImageMagick: PALM and DCM buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: PALM and DCM buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.3.0.5"), vulnerable: make_list("lt 6.3.0.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
