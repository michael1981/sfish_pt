# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-15.xml
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
 script_id(35813);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-15");
 script_cve_id("CVE-2008-5516", "CVE-2008-5517", "CVE-2008-5916");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-15
(git: Multiple vulnerabilties)


    Multiple vulnerabilities have been reported in gitweb that is part of
    the git package:
    Shell metacharacters related to git_search are not properly sanitized
    (CVE-2008-5516).
    Shell metacharacters related to git_snapshot and git_object are not
    properly sanitized (CVE-2008-5517).
    The diff.external configuration variable as set in a repository can be
    executed by gitweb (CVE-2008-5916).
  
Impact

    A remote unauthenticated attacker can execute arbitrary commands via
    shell metacharacters in a query, remote attackers with write access to
    a git repository configuration can execute arbitrary commands with the
    privileges of the user running gitweb by modifying the diff.external
    configuration variable in the repository and sending a crafted query to
    gitweb.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All git users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/git-1.6.0.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5516');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5517');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5916');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-15] git: Multiple vulnerabilties');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'git: Multiple vulnerabilties');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/git", unaffected: make_list("ge 1.6.0.6"), vulnerable: make_list("lt 1.6.0.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
