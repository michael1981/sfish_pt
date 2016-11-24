# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-10.xml
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
 script_id(25792);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200707-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-10
(Festival: Privilege elevation)


    Konstantine Shirow reported a vulnerability in default Gentoo
    configurations of Festival. The daemon is configured to run with root
    privileges and to listen on localhost, without requiring a password.
  
Impact

    A local attacker could gain root privileges by connecting to the daemon
    and execute arbitrary commands.
  
Workaround

    Set a password in the configuration file /etc/festival/server.scm by
    adding the line: (set! server_passwd password)
  
');
script_set_attribute(attribute:'solution', value: '
    All Festival users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-accessibility/festival-1.95_beta-r4"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-10] Festival: Privilege elevation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Festival: Privilege elevation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-accessibility/festival", unaffected: make_list("ge 1.95_beta-r4"), vulnerable: make_list("lt 1.95_beta-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
