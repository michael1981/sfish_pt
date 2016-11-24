# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-15.xml
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
 script_id(14480);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-15");
 script_cve_id("CVE-2004-0409");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-15
(XChat 2.0.x SOCKS5 Vulnerability)


    The SOCKS 5 proxy code in XChat is vulnerable to a remote exploit.
    Users would have to be using XChat through a SOCKS 5 server, enable
    SOCKS 5 traversal which is disabled by default and also connect to an
    attacker\'s custom proxy server.
  
Impact

    This vulnerability may allow an attacker to run arbitrary code within
    the context of the user ID of the XChat client.
  
Workaround

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All XChat users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-irc/xchat-2.0.8-r1"
    # emerge ">=net-irc/xchat-2.0.8-r1"
    Note that users of the gtk1 version of xchat (1.8.*) should upgrade to
    xchat-1.8.11-r1:
    # emerge sync
    # emerge -pv "=net-irc/xchat-1.8.11-r1"
    # emerge "=net-irc/xchat-1.8.11-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://mail.nl.linux.org/xchat-announce/2004-04/msg00000.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0409');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-15] XChat 2.0.x SOCKS5 Vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XChat 2.0.x SOCKS5 Vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/xchat", unaffected: make_list("ge 2.0.8-r1"), vulnerable: make_list("lt 2.0.8-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
