# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-10.xml
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
 script_id(20330);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-10
(Opera: Command-line URL shell command injection)


    Peter Zelezny discovered that the shell script used to launch
    Opera parses shell commands that are enclosed within backticks in the
    URL provided via the command line.
  
Impact

    A remote attacker could exploit this vulnerability by enticing a
    user to follow a specially crafted URL from a tool that uses Opera to
    open URLs, resulting in the execution of arbitrary commands on the
    targeted machine.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-8.51"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3750');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/docs/changelogs/linux/851/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-10] Opera: Command-line URL shell command injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Command-line URL shell command injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 8.51"), vulnerable: make_list("lt 8.51")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
