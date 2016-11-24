# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-19.xml
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
 script_id(14575);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-19");
 script_cve_id("CVE-2004-0777");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-19
(courier-imap: Remote Format String Vulnerability)


    There is a format string vulnerability in the auth_debug() function
    which can be exploited remotely, potentially leading to arbitrary code
    execution as the user running the IMAP daemon (oftentimes root). A
    remote attacker may send username or password information containing
    printf() format tokens (such as "%s"), which will crash the server or
    cause it to execute arbitrary code.
    This vulnerability can only be exploited if DEBUG_LOGIN is set to
    something other than 0 in the imapd config file.
  
Impact

    If DEBUG_LOGIN is enabled in the imapd configuration, a remote attacker
    may execute arbitrary code as the root user.
  
Workaround

    Set the DEBUG_LOGIN option in /etc/courier-imap/imapd to 0. (This is
    the default value.)
  
');
script_set_attribute(attribute:'solution', value: '
    All courier-imap users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-mail/courier-imap-3.0.5"
    # emerge ">=net-mail/courier-imap-3.0.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=131&type=vulnerabilities&flashstatus=true');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0777');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-19] courier-imap: Remote Format String Vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'courier-imap: Remote Format String Vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/courier-imap", unaffected: make_list("ge 3.0.5"), vulnerable: make_list("le 3.0.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
