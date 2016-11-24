# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-10.xml
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
 script_id(30089);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200801-10");
 script_cve_id("CVE-2007-6526", "CVE-2007-6528", "CVE-2007-6529");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-10
(TikiWiki: Multiple vulnerabilities)


    Jesus Olmos Gonzalez from isecauditors reported insufficient
    sanitization of the "movies" parameter in file tiki-listmovies.php
    (CVE-2007-6528).
    Mesut Timur from H-Labs discovered that the
    input passed to the "area_name" parameter in file
    tiki-special_chars.php is not properly sanitised before being returned
    to the user (CVE-2007-6526).
    redflo reported multiple
    unspecified vulnerabilities in files tiki-edit_css.php,
    tiki-list_games.php, and tiki-g-admin_shared_source.php
    (CVE-2007-6529).
  
Impact

    A remote attacker can craft the "movies" parameter to run a directory
    traversal attack through a ".." sequence and read the first 1000 bytes
    of any arbitrary file, or conduct a cross-site scripting (XSS) attack
    through the "area_name" parameter. This attack can be exploited to
    execute arbitrary HTML and script code in a user\'s browser session,
    allowing for the theft of browser session data or cookies in the
    context of the affected web site. The impacts of the unspecified
    vulnerabilities are still unknown.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.9.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6526');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6528');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6529');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-10] TikiWiki: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TikiWiki: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.9.9"), vulnerable: make_list("lt 1.9.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
