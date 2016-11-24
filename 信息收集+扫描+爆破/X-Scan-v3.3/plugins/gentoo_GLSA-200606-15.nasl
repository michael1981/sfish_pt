# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-15.xml
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
 script_id(21708);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200606-15");
 script_cve_id("CVE-2006-2898");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-15
(Asterisk: IAX2 video frame buffer overflow)


    Asterisk fails to properly check the length of truncated video frames
    in the IAX2 channel driver which results in a buffer overflow.
  
Impact

    An attacker could exploit this vulnerability by sending a specially
    crafted IAX2 video stream resulting in the execution of arbitrary code
    with the permissions of the user running Asterisk.
  
Workaround

    Disable public IAX2 support.
  
');
script_set_attribute(attribute:'solution', value: '
    All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/asterisk-1.0.11_p1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2898');
script_set_attribute(attribute: 'see_also', value: 'http://www.coresecurity.com/common/showdoc.php?idx=547&idxseccion=10');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-15] Asterisk: IAX2 video frame buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Asterisk: IAX2 video frame buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/asterisk", unaffected: make_list("ge 1.0.11_p1"), vulnerable: make_list("lt 1.0.11_p1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
