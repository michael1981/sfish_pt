# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-06.xml
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
 script_id(33473);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200807-06");
 script_cve_id("CVE-2007-6420", "CVE-2008-1678", "CVE-2008-2364");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-06
(Apache: Denial of Service)


    Multiple vulnerabilities have been discovered in Apache:
    Dustin Kirkland reported that the mod_ssl module can leak memory when
    the client reports support for a compression algorithm (CVE-2008-1678).
    Ryujiro Shibuya reported that the ap_proxy_http_process_response()
    function in the mod_proxy module does not limit the number of forwarded
    interim responses (CVE-2008-2364).
    sp3x of SecurityReason reported a Cross-Site Request Forgery
    vulnerability in the balancer-manager in the mod_proxy_balancer module
    (CVE-2007-6420).
  
Impact

    A remote attacker could exploit these vulnerabilities by connecting to
    an Apache httpd, by causing an Apache proxy server to connect to a
    malicious server, or by enticing a balancer administrator to connect to
    a specially-crafted URL, resulting in a Denial of Service of the Apache
    daemon.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.2.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6420');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1678');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2364');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-06] Apache: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.2.9"), vulnerable: make_list("lt 2.2.9")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
