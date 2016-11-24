# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-02.xml
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
 script_id(20281);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-02
(Webmin, Usermin: Format string vulnerability)


    Jack Louis discovered that the Webmin and Usermin "miniserv.pl"
    web server component is vulnerable to a Perl format string
    vulnerability. Login with the supplied username is logged via the Perl
    "syslog" facility in an unsafe manner.
  
Impact

    A remote attacker can trigger this vulnerability via a specially
    crafted username containing format string data. This can be exploited
    to consume a large amount of CPU and memory resources on a vulnerable
    system, and possibly to execute arbitrary code of the attacker\'s choice
    with the permissions of the user running Webmin.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Webmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/webmin-1.250"
    All Usermin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/usermin-1.180"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3912');
script_set_attribute(attribute: 'see_also', value: 'http://www.dyadsecurity.com/webmin-0001.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-02] Webmin, Usermin: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.180"), vulnerable: make_list("lt 1.180")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.250"), vulnerable: make_list("lt 1.250")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
