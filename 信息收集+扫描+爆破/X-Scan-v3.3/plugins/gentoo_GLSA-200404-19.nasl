# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-19.xml
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
 script_id(14484);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200404-19");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-19
(Buffer overflows and format string vulnerabilities in LCDproc)


    Due to insufficient checking of client-supplied data, the LCDd server is
    susceptible to two buffer overflows and one string buffer vulnerability. If
    the server is configured to listen on all network interfaces (see the Bind
    parameter in LCDproc configuration), these vulnerabilities can be triggered
    remotely.
  
Impact

    These vulnerabilities allow an attacker to execute code with the rights of
    the user running the LCDproc server. By default, this is the "nobody" user.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    LCDproc users should upgrade to version 0.4.5 or later:
    # emerge sync
    # emerge -pv ">=app-misc/lcdproc-0.4.5"
    # emerge ">=app-misc/lcdproc-0.4.5"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://lists.omnipotent.net/pipermail/lcdproc/2004-April/008884.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-19] Buffer overflows and format string vulnerabilities in LCDproc');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer overflows and format string vulnerabilities in LCDproc');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-misc/lcdproc", unaffected: make_list("ge 0.4.5"), vulnerable: make_list("le 0.4.4-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
