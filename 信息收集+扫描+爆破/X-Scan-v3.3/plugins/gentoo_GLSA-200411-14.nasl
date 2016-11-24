# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-14.xml
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
 script_id(15648);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200411-14");
 script_cve_id("CVE-2004-1034");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-14
(Kaffeine, gxine: Remotely exploitable buffer overflow)


    KF of Secure Network Operations has discovered an overflow that occurs
    during the Content-Type header processing of Kaffeine. The vulnerable
    code in Kaffeine is reused from gxine, making gxine vulnerable as well.
  
Impact

    An attacker could create a specially-crafted Content-type header from a
    malicious HTTP server, and crash a user\'s instance of Kaffeine or
    gxine, potentially allowing the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Kaffeine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/kaffeine-0.4.3b-r1"
    All gxine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/gxine-0.3.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://securitytracker.com/alerts/2004/Oct/1011936.html');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/tracker/index.php?func=detail&aid=1060299&group_id=9655&atid=109655');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1034');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-14] Kaffeine, gxine: Remotely exploitable buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kaffeine, gxine: Remotely exploitable buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/gxine", unaffected: make_list("ge 0.3.3-r1"), vulnerable: make_list("lt 0.3.3-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-video/kaffeine", unaffected: make_list("ge 0.5_rc1-r1", "rge 0.4.3b-r1"), vulnerable: make_list("lt 0.5_rc1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
