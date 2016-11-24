# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-19.xml
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
 script_id(31445);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-19");
 script_cve_id("CVE-2007-6203", "CVE-2007-6422", "CVE-2008-0005", "CVE-2008-0455", "CVE-2008-0456");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-19
(Apache: Multiple vulnerabilities)


    Adrian Pastor and Amir Azam (ProCheckUp) reported that the HTTP Method
    specifier header is not properly sanitized when the HTTP return code is
    "413 Request Entity too large" (CVE-2007-6203). The mod_proxy_balancer
    module does not properly check the balancer name before using it
    (CVE-2007-6422). The mod_proxy_ftp does not define a charset in its
    answers (CVE-2008-0005). Stefano Di Paola (Minded Security) reported
    that filenames are not properly sanitized within the mod_negotiation
    module (CVE-2008-0455, CVE-2008-0456).
  
Impact

    A remote attacker could entice a user to visit a malicious URL or send
    specially crafted HTTP requests (i.e using Adobe Flash) to perform
    Cross-Site Scripting and HTTP response splitting attacks, or conduct a
    Denial of Service attack on the vulnerable web server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.2.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6203');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6422');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0005');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0455');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0456');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-19] Apache: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.2.8"), vulnerable: make_list("lt 2.2.8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
