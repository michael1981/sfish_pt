# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-21.xml
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
 script_id(32014);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200804-21");
 script_cve_id("CVE-2007-0071", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243", "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-21
(Adobe Flash Player: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Adobe Flash:
    Secunia Research and Zero Day Initiative reported a boundary error
    related to DeclareFunction2 Actionscript tags in SWF files
    (CVE-2007-6019).
    The ISS X-Force and the Zero Day Initiative reported an unspecified
    input validation error that might lead to a buffer overflow
    (CVE-2007-0071).
    Microsoft, UBsecure and JPCERT/CC reported that cross-domain policy
    files are not checked before sending HTTP headers to another domain
    (CVE-2008-1654) and that it does not sufficiently restrict the
    interpretation and usage of cross-domain policy files (CVE-2007-6243).
    The Stanford University and Ernst and Young\'s Advanced Security Center
    reported that Flash does not pin DNS hostnames to a single IP
    addresses, allowing for DNS rebinding attacks (CVE-2007-5275,
    CVE-2008-1655).
    The Google Security Team and Minded Security Multiple reported multiple
    cross-site scripting vulnerabilities when passing input to Flash
    functions (CVE-2007-6637).
  
Impact

    A remote attacker could entice a user to open a specially crafted file
    (usually in a web browser), possibly leading to the execution of
    arbitrary code with the privileges of the user running the Adobe Flash
    Player. The attacker could also cause a user\'s machine to send HTTP
    requests to other hosts, establish TCP sessions with arbitrary hosts,
    bypass the security sandbox model, or conduct Cross-Site Scripting and
    Cross-Site Request Forgery attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-plugins/adobe-flash-9.0.124.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0071');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5275');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6019');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6243');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6637');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1654');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1655');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-21] Adobe Flash Player: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Flash Player: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-plugins/adobe-flash", unaffected: make_list("ge 9.0.124.0"), vulnerable: make_list("lt 9.0.124.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
