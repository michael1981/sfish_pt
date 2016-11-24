# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-06.xml
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
 script_id(16397);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200501-06");
 script_cve_id("CVE-2004-1183", "CVE-2004-1308");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-06
(tiff: New overflows in image decoding)


    infamous41md found a potential integer overflow in the directory
    entry count routines of the TIFF library (CAN-2004-1308). Dmitry V.
    Levin found another similar issue in the tiffdump utility
    (CAN-2004-1183).
  
Impact

    A remote attacker could entice a user to view a carefully crafted
    TIFF image file, which would potentially lead to execution of arbitrary
    code with the rights of the user viewing the image. This affects any
    program that makes use of the TIFF library, including many web browsers
    or mail readers.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All TIFF library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.7.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1183');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1308');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=174&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-06] tiff: New overflows in image decoding');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'tiff: New overflows in image decoding');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.7.1-r1"), vulnerable: make_list("lt 3.7.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
