# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-14.xml
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
 script_id(24839);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-14");
 script_cve_id("CVE-2007-1306");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-14
(Asterisk: SIP Denial of Service)


    The MU Security Research Team discovered that Asterisk contains a
    NULL-pointer dereferencing error in the SIP channel when handling
    request messages.
  
Impact

    A remote attacker could cause an Asterisk server listening for SIP
    messages to crash by sending a specially crafted SIP request message.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-misc/asterisk
    Note: Asterisk 1.0.x is no longer supported upstream so users should
    consider upgrading to Asterisk 1.2.x.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1306');
script_set_attribute(attribute: 'see_also', value: 'http://labs.musecurity.com/advisories/MU-200703-01.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-14] Asterisk: SIP Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Asterisk: SIP Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/asterisk", unaffected: make_list("ge 1.2.14-r1", "rge 1.0.12-r1"), vulnerable: make_list("lt 1.2.14-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
