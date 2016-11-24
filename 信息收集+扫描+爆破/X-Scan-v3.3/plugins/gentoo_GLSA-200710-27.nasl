# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-27.xml
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
 script_id(27559);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-27");
 script_cve_id("CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-27
(ImageMagick: Multiple vulnerabilities)


    regenrecht reported multiple infinite loops in functions ReadDCMImage()
    and ReadXCFImage() (CVE-2007-4985), multiple integer overflows when
    handling certain types of images (CVE-2007-4986, CVE-2007-4988), and an
    off-by-one error in the ReadBlobString() function (CVE-2007-4987).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    image, possibly resulting in the remote execution of arbitrary code
    with the privileges of the user running the application, or an
    excessive CPU consumption. Note that applications relying on
    ImageMagick to process images can also trigger the vulnerability.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.3.5.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4985');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4986');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4987');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4988');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-27] ImageMagick: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.3.5.10"), vulnerable: make_list("lt 6.3.5.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
