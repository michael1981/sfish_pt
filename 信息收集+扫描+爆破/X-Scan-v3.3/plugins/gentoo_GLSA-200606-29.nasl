# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-29.xml
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
 script_id(21775);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200606-29");
 script_cve_id("CVE-2006-3048", "CVE-2006-3047");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-29
(Tikiwiki: SQL injection and multiple XSS vulnerabilities)


    Tikiwiki fails to properly sanitize user input before processing it,
    including in SQL statements.
  
Impact

    An attacker could execute arbitrary SQL statements on the underlying
    database, or inject arbitrary scripts into the context of a user\'s
    browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Tikiwiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.9.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3048');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3047');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-29] Tikiwiki: SQL injection and multiple XSS vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tikiwiki: SQL injection and multiple XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.9.4"), vulnerable: make_list("lt 1.9.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
