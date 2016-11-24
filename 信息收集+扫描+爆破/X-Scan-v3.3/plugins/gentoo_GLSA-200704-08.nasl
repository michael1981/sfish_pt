# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-08.xml
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
 script_id(25053);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200704-08");
 script_cve_id("CVE-2006-6965");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-08
(DokuWiki: Cross-site scripting vulnerability)


    DokuWiki does not sanitize user input to the GET variable \'media\' in
    the fetch.php file.
  
Impact

    An attacker could entice a user to click a specially crafted link and
    inject CRLF characters into the variable. This would allow the creation
    of new lines or fields in the returned HTTP Response header, which
    would permit the attacker to execute arbitrary scripts in the context
    of the user\'s browser.
  
Workaround

    Replace the following line in lib/exe/fetch.php:
    $MEDIA = getID(\'media\',false); // no cleaning - maybe external
    with
    $MEDIA = preg_replace(\'/[\\x00-\\x1F]+/s\',\'\',getID(\'media\',false));
  
');
script_set_attribute(attribute:'solution', value: '
    All DokuWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/dokuwiki-20061106"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6965');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-08] DokuWiki: Cross-site scripting vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DokuWiki: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/dokuwiki", unaffected: make_list("ge 20061106"), vulnerable: make_list("lt 20061106")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
