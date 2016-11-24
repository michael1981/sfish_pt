# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200811-02.xml
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
 script_id(34733);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200811-02");
 script_cve_id("CVE-2008-3600", "CVE-2008-3662", "CVE-2008-4129", "CVE-2008-4130");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200811-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200811-02
(Gallery: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Gallery 1 and 2:
    Digital Security Research Group reported a directory traversal
    vulnerability in contrib/phpBB2/modules.php in Gallery 1, when
    register_globals is enabled (CVE-2008-3600).
    Hanno Boeck reported that Gallery 1 and 2 did not set the secure flag
    for the session cookie in an HTTPS session (CVE-2008-3662).
    Alex Ustinov reported that Gallery 1 and 2 does not properly handle ZIP
    archives containing symbolic links (CVE-2008-4129).
    The vendor reported a Cross-Site Scripting vulnerability in Gallery 2
    (CVE-2008-4130).
  
Impact

    Remote attackers could send specially crafted requests to a server
    running Gallery, allowing for the execution of arbitrary code when
    register_globals is enabled, or read arbitrary files via directory
    traversals otherwise. Attackers could also entice users to visit
    crafted links allowing for theft of login credentials.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gallery 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/gallery-2.2.6"
    All Gallery 1 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/gallery-1.5.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3600');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3662');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4129');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4130');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200811-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200811-02] Gallery: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 2.2.6", "rge 1.5.9", "rge 1.5.10"), vulnerable: make_list("lt 2.2.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
