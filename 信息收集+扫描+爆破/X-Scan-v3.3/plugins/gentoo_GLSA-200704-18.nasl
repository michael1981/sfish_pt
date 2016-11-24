# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-18.xml
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
 script_id(25106);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200704-18");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-18
(Courier-IMAP: Remote execution of arbitrary code)


    CJ Kucera has discovered that some Courier-IMAP scripts don\'t properly
    handle the XMAILDIR variable, allowing for shell command injection.
  
Impact

    A remote attacker could send specially crafted login credentials to a
    Courier-IMAP server instance, possibly leading to remote code execution
    with root privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Courier-IMAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/courier-imap-4.0.6-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-18] Courier-IMAP: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Courier-IMAP: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/courier-imap", unaffected: make_list("ge 4.0.6-r2", "lt 4.0.0"), vulnerable: make_list("lt 4.0.6-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
