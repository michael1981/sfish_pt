# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-20.xml
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
 script_id(18384);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-20");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-20
(Mailutils: Multiple vulnerabilities in imap4d and mail)


    infamous41d discovered several vulnerabilities in GNU Mailutils.
    imap4d does not correctly implement formatted printing of command tags
    (CAN-2005-1523), fails to validate the range sequence of the "FETCH"
    command (CAN-2005-1522), and contains an integer overflow in the
    "fetch_io" routine (CAN-2005-1521). mail contains a buffer overflow in
    "header_get_field_name()" (CAN-2005-1520).
  
Impact

    A remote attacker can exploit the format string and integer
    overflow in imap4d to execute arbitrary code as the imap4d user, which
    is usually root. By sending a specially crafted email message, a remote
    attacker could exploit the buffer overflow in the "mail" utility to
    execute arbitrary code with the rights of the user running mail.
    Finally, a remote attacker can also trigger a Denial of Service by
    sending a malicious FETCH command to an affected imap4d, causing
    excessive resource consumption.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Mailutils users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailutils-0.6-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1520');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1521');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1522');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1523');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?type=vulnerabilities&showYear=2005');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-20] Mailutils: Multiple vulnerabilities in imap4d and mail');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailutils: Multiple vulnerabilities in imap4d and mail');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/mailutils", unaffected: make_list("ge 0.6-r1"), vulnerable: make_list("lt 0.6-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
