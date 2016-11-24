# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-34.xml
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
 script_id(16425);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-34");
 script_cve_id("CVE-2005-0129", "CVE-2005-0130", "CVE-2005-0131");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-34 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-34
(Konversation: Various vulnerabilities)


    Wouter Coekaerts has discovered three vulnerabilites within
    Konversation:
    The Server::parseWildcards function, which
    is used by the "Quick Buttons", does not properly handle variable
    expansion (CAN-2005-0129).
    Perl scripts included with
    Konversation do not properly escape shell metacharacters
    (CAN-2005-0130).
    The \'Nick\' and \'Password\' fields in the Quick
    Connect dialog can be easily confused (CAN-2005-0131).
  
Impact

    A malicious server could create specially-crafted channels, which
    would exploit certain flaws in Konversation, potentially leading to the
    execution of shell commands. A user could also unintentionally input
    their password into the \'Nick\' field in the Quick Connect dialog,
    exposing his password to IRC users, and log files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Konversation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/konversation-0.15.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0129');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0130');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0131');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20050121-1.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-34.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-34] Konversation: Various vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Konversation: Various vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/konversation", unaffected: make_list("ge 0.15.1"), vulnerable: make_list("lt 0.15.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
