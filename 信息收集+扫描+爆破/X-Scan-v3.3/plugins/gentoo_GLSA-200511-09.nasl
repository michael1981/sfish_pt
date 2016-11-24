# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-09.xml
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
 script_id(20196);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200511-09");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-09
(Lynx: Arbitrary command execution)


    iDefense labs discovered a problem within the feature to execute
    local cgi-bin programs via the "lynxcgi:" URI handler. Due to a
    configuration error, the default settings allow websites to specify
    commands to run as the user running Lynx.
  
Impact

    A remote attacker can entice a user to access a malicious HTTP
    server, causing Lynx to execute arbitrary commands.
  
Workaround

    Disable "lynxcgi" links by specifying the following directive in
    lynx.cfg:
    TRUSTED_LYNXCGI:none
  
');
script_set_attribute(attribute:'solution', value: '
    All Lynx users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/lynx-2.8.5-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2929');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=338&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-09] Lynx: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Lynx: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/lynx", unaffected: make_list("ge 2.8.5-r2"), vulnerable: make_list("lt 2.8.5-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
