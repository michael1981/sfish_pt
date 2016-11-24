# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-36.xml
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
 script_id(16427);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-36");
 script_cve_id("CVE-2005-0116", "CVE-2005-0362", "CVE-2005-0363");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-36 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-36
(AWStats: Remote code execution)


    When \'awstats.pl\' is run as a CGI script, it fails to validate specific
    inputs which are used in a Perl open() function call. Furthermore, a
    user could read log file content even when plugin rawlog was not
    enabled.
  
Impact

    A remote attacker could supply AWStats malicious input, potentially
    allowing the execution of arbitrary code with the rights of the web
    server. He could also access raw log contents.
  
Workaround

    Making sure that AWStats does not run as a CGI script will avoid the
    issue, but we recommend that users upgrade to the latest version, which
    fixes these bugs.
  
');
script_set_attribute(attribute:'solution', value: '
    All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-misc/awstats-6.3-r2"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://awstats.sourceforge.net/docs/awstats_changelog.txt');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=185');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0116');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0362');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0363');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-36.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-36] AWStats: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AWStats: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-misc/awstats", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
