# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-09.xml
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
 script_id(16400);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-09");
 script_cve_id("CVE-2004-0994");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-09
(xzgv: Multiple overflows)


    Multiple overflows have been found in the image processing code of
    xzgv, including an integer overflow in the PRF parsing code
    (CAN-2004-0994).
  
Impact

    An attacker could entice a user to open or browse a
    specially-crafted image file, potentially resulting in the execution of
    arbitrary code with the rights of the user running xzgv.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xzgv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xzgv-0.8-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0994');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=160&type=vulnerabilities&flashstatus=true');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-09] xzgv: Multiple overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xzgv: Multiple overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/xzgv", unaffected: make_list("ge 0.8-r1"), vulnerable: make_list("le 0.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
