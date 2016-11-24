# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-34.xml
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
 script_id(15833);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200411-34");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-34 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-34
(Cyrus IMAP Server: Multiple remote vulnerabilities)


    Multiple vulnerabilities have been discovered in the argument
    parsers of the \'partial\' and \'fetch\' commands of the Cyrus IMAP Server
    (CAN-2004-1012, CAN-2004-1013). There are also buffer overflows in the
    \'imap magic plus\' code that are vulnerable to exploitation as well
    (CAN-2004-1011, CAN-2004-1015).
  
Impact

    An attacker can exploit these vulnerabilities to execute arbitrary
    code with the rights of the user running the Cyrus IMAP Server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cyrus-IMAP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/cyrus-imapd-2.2.10"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1011');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1012');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1013');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1015');
script_set_attribute(attribute: 'see_also', value: 'http://security.e-matters.de/advisories/152004.html');
script_set_attribute(attribute: 'see_also', value: 'http://asg.web.cmu.edu/cyrus/download/imapd/changes.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-34.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-34] Cyrus IMAP Server: Multiple remote vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cyrus IMAP Server: Multiple remote vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/cyrus-imapd", unaffected: make_list("ge 2.2.10"), vulnerable: make_list("lt 2.2.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
