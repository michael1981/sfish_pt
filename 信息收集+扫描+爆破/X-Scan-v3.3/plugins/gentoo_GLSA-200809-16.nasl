# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-16.xml
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
 script_id(34297);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200809-16");
 script_cve_id("CVE-2008-3546");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-16
(Git: User-assisted execution of arbitrary code)


    Multiple boundary errors in the functions diff_addremove() and
    diff_change() when processing overly long repository path names were
    reported.
  
Impact

    A remote attacker could entice a user to run commands like "git-diff"
    or "git-grep" on a specially crafted repository, possibly resulting in
    the remote execution of arbitrary code with the privileges of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Git users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/git-1.5.6.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3546');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-16] Git: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Git: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/git", unaffected: make_list("ge 1.5.6.4"), vulnerable: make_list("lt 1.5.6.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
