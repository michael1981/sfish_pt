# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-20.xml
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
 script_id(20264);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200511-20");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-20
(Horde Application Framework: XSS vulnerability)


    The Horde Team reported a potential XSS vulnerability. Horde fails
    to properly escape error messages which may lead to displaying
    unsanitized error messages via Notification_Listener::getMessage()
  
Impact

    By enticing a user to read a specially-crafted e-mail or using a
    manipulated URL, an attacker can execute arbitrary scripts running in
    the context of the victim\'s browser. This could lead to a compromise of
    the user\'s browser content.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde Application Framework users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-2.2.9"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Low');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3570');
script_set_attribute(attribute: 'see_also', value: 'http://lists.horde.org/archives/announce/2005/000231.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-20] Horde Application Framework: XSS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Application Framework: XSS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 2.2.9"), vulnerable: make_list("lt 2.2.9")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
