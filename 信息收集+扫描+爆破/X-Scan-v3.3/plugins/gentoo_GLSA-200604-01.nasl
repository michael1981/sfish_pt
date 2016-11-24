# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-01.xml
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
 script_id(21194);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200604-01");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200604-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200604-01
(MediaWiki: Cross-site scripting vulnerability)


    MediaWiki fails to decode certain encoded URLs correctly.
  
Impact

    By supplying specially crafted links, a remote attacker could
    exploit this vulnerability to inject malicious HTML or JavaScript code
    that will be executed in a user\'s browser session in the context of the
    vulnerable site.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MediaWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mediawiki-1.4.15"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Low');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1498');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/project/shownotes.php?release_id=404869');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200604-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200604-01] MediaWiki: Cross-site scripting vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MediaWiki: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/mediawiki", unaffected: make_list("ge 1.4.15"), vulnerable: make_list("lt 1.4.15")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
