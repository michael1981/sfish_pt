# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-37.xml
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
 script_id(16428);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-37");
 script_cve_id("CVE-2005-0005");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-37 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-37
(GraphicsMagick: PSD decoding heap overflow)


    Andrei Nigmatulin discovered that handling a Photoshop Document
    (PSD) file with more than 24 layers in ImageMagick could trigger a heap
    overflow (GLSA 200501-26). GraphicsMagick is based on the same code and
    therefore suffers from the same flaw.
  
Impact

    An attacker could potentially design a malicious PSD image file to
    cause arbitrary code execution with the permissions of the user running
    GraphicsMagick.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GraphicsMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/graphicsmagick-1.1.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0005');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-26.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-37.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-37] GraphicsMagick: PSD decoding heap overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GraphicsMagick: PSD decoding heap overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/graphicsmagick", unaffected: make_list("ge 1.1.5"), vulnerable: make_list("lt 1.1.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
