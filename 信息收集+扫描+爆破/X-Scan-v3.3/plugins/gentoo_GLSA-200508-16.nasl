# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-16.xml
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
 script_id(19536);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200508-16");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-16
(Tor: Information disclosure)


    The Diffie-Hellman implementation of Tor fails to verify the
    cryptographic strength of keys which are used during handshakes.
  
Impact

    By setting up a malicious Tor server and enticing users to use
    this server as first hop, a remote attacker could read and modify all
    traffic of the user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Tor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/tor-0.1.0.14"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Low');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2643');
script_set_attribute(attribute: 'see_also', value: 'http://archives.seul.org/or/announce/Aug-2005/msg00002.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-16] Tor: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tor: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/tor", unaffected: make_list("ge 0.1.0.14"), vulnerable: make_list("lt 0.1.0.14")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
