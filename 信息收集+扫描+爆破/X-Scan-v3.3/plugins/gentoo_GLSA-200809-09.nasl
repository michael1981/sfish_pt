# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-09.xml
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
 script_id(34248);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200809-09");
 script_cve_id("CVE-2008-3889");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-09
(Postfix: Denial of Service)


    It has been discovered than Postfix leaks an epoll file descriptor when
    executing external commands, e.g. user-controlled $HOME/.forward or
    $HOME/.procmailrc files. NOTE: This vulnerability only concerns Postfix
    instances running on Linux 2.6 kernels.
  
Impact

    A local attacker could exploit this vulnerability to reduce the
    performance of Postfix, and possibly trigger an assertion, resulting in
    a Denial of Service.
  
Workaround

    Allow only trusted users to control delivery to non-Postfix commands.
  
');
script_set_attribute(attribute:'solution', value: '
    All Postfix 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/postfix-2.4.9"
    All Postfix 2.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/postfix-2.5.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3889');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-09] Postfix: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Postfix: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/postfix", unaffected: make_list("ge 2.4.9", "ge 2.5.5"), vulnerable: make_list("lt 2.4.9", "lt 2.5.5")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
