# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-18.xml
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
 script_id(19231);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-18");
 script_cve_id("CVE-2005-2396");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-18
(MediaWiki: Cross-site scripting vulnerability)


    MediaWiki fails to escape a parameter in the page move template
    correctly.
  
Impact

    By enticing a user to visit a specially crafted URL, a remote attacker
    could exploit this vulnerability to inject malicious JavaScript code
    that will be executed in a user\'s browser session in the context of the
    vulnerable site.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MediaWiki users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mediawiki-1.4.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2396');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/project/shownotes.php?release_id=342530');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-18] MediaWiki: Cross-site scripting vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MediaWiki: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/mediawiki", unaffected: make_list("ge 1.4.6"), vulnerable: make_list("lt 1.4.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
