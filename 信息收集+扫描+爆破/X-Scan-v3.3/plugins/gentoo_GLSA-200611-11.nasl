# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-11.xml
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
 script_id(23705);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-11");
 script_cve_id("CVE-2006-5702", "CVE-2006-5703");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-11
(TikiWiki: Multiple vulnerabilities)


    In numerous files TikiWiki provides an empty sort_mode parameter,
    causing TikiWiki to display additional information, including database
    authentication credentials, in certain error messages. TikiWiki also
    improperly sanitizes the "url" request variable sent to
    tiki-featured_link.php.
  
Impact

    An attacker could cause a database error in various pages of a TikiWiki
    instance by providing an empty sort_mode request variable, and gain
    unauthorized access to credentials of the MySQL databases used by
    TikiWiki. An attacker could also entice a user to browse to a specially
    crafted URL that could run scripts in the scope of the user\'s browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.9.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5702');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5703');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-11] TikiWiki: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TikiWiki: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.9.6"), vulnerable: make_list("lt 1.9.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
