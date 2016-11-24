# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-10.xml
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
 script_id(20030);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200510-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-10
(uw-imap: Remote buffer overflow)


    Improper bounds checking of user supplied data while parsing IMAP
    mailbox names can lead to overflowing the stack buffer.
  
Impact

    Successful exploitation requires an authenticated IMAP user to
    request a malformed mailbox name. This can lead to execution of
    arbitrary code with the permissions of the IMAP server.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All uw-imap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/uw-imap-2004g"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2933');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=313&type=vulnerabilities&flashstatus=false');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-10] uw-imap: Remote buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'uw-imap: Remote buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/uw-imap", unaffected: make_list("ge 2004g"), vulnerable: make_list("lt 2004g")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
