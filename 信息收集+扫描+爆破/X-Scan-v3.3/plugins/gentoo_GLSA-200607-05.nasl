# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-05.xml
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
 script_id(22012);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200607-05");
 script_cve_id("CVE-2006-3007", "CVE-2006-3534", "CVE-2006-3535");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200607-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200607-05
(SHOUTcast server: Multiple vulnerabilities)


    The SHOUTcast server is vulnerable to a file disclosure when the server
    receives a specially crafted GET request. Furthermore it also fails to
    sanitize the input passed to the "Description", "URL", "Genre", "AIM",
    and "ICQ" fields.
  
Impact

    By sending a specially crafted GET request to the SHOUTcast server, the
    attacker can read any file that can be read by the SHOUTcast process.
    Furthermore it is possible that various request variables could also be
    exploited to execute arbitrary scripts in the context of a victim\'s
    browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SHOUTcast server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/shoutcast-server-bin-1.9.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://people.ksp.sk/~goober/advisory/001-shoutcast.html');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/20524/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3007');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3534');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3535');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200607-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200607-05] SHOUTcast server: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SHOUTcast server: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/shoutcast-server-bin", unaffected: make_list("ge 1.9.7"), vulnerable: make_list("lt 1.9.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
