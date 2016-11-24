# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-07.xml
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
 script_id(16398);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-07");
 script_cve_id("CVE-2004-1187", "CVE-2004-1188", "CVE-2004-1300");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-07
(xine-lib: Multiple overflows)


    Ariel Berkman discovered that xine-lib reads specific input data
    into an array without checking the input size in demux_aiff.c, making
    it vulnerable to a buffer overflow (CAN-2004-1300) . iDefense
    discovered that the PNA_TAG handling code in pnm_get_chunk() does not
    check if the input size is larger than the buffer size (CAN-2004-1187).
    iDefense also discovered that in this same function, a negative value
    could be given to an unsigned variable that specifies the read length
    of input data (CAN-2004-1188).
  
Impact

    A remote attacker could craft a malicious movie or convince a
    targeted user to connect to a malicious PNM server, which could result
    in the execution of arbitrary code with the rights of the user running
    any xine-lib frontend.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/xine-lib
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1187');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1188');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1300');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=176&type=vulnerabilities');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=177&type=vulnerabilities');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/xine-lib.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-07] xine-lib: Multiple overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Multiple overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc8-r1", "rge 1_rc6-r1"), vulnerable: make_list("lt 1_rc8-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
