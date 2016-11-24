# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-13.xml
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
 script_id(27048);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-13");
 script_cve_id("CVE-2007-4437", "CVE-2007-4438");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-13
(Ampache: Multiple vulnerabilities)


    LT discovered that the "match" parameter in albums.php is not properly
    sanitized before being processed. The Ampache development team also
    reported an error when handling user sessions.
  
Impact

    A remote attacker could provide malicious input to the application,
    possibly resulting in the execution of arbitrary SQL code. He could
    also entice a user to open a specially crafted link to steal the user\'s
    session.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ampache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/ampache-3.3.3.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4437');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4438');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-13] Ampache: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ampache: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/ampache", unaffected: make_list("ge 3.3.3.5"), vulnerable: make_list("lt 3.3.3.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
