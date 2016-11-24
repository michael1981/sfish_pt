# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-07.xml
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
 script_id(30031);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200801-07");
 script_cve_id("CVE-2007-4324", "CVE-2007-4768", "CVE-2007-5275", "CVE-2007-6242", "CVE-2007-6243", "CVE-2007-6244", "CVE-2007-6245", "CVE-2007-6246");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-07
(Adobe Flash Player: Multiple vulnerabilities)


    Flash contains a copy of PCRE which is vulnerable to a heap-based
    buffer overflow (GLSA 200711-30, CVE-2007-4768).
    Aaron Portnoy reported an unspecified vulnerability related to
    input validation (CVE-2007-6242).
    Jesse Michael and Thomas Biege reported that Flash does not
    correctly set memory permissions (CVE-2007-6246).
    Dan Boneh, Adam Barth, Andrew Bortz, Collin Jackson, and Weidong
    Shao reported that Flash does not pin DNS hostnames to a single IP
    addresses, allowing for DNS rebinding attacks (CVE-2007-5275).
    David Neu reported an error withing the implementation of the
    Socket and XMLSocket ActionScript 3 classes (CVE-2007-4324).
    Toshiharu Sugiyama reported that Flash does not sufficiently
    restrict the interpretation and usage of cross-domain policy files,
    allowing for easier cross-site scripting attacks (CVE-2007-6243).
    Rich Cannings reported a cross-site scripting vulnerability in the
    way the "asfunction:" protocol was handled (CVE-2007-6244).
    Toshiharu Sugiyama discovered that Flash allows remote attackers to
    modify HTTP headers for client requests and conduct HTTP Request
    Splitting attacks (CVE-2007-6245).
  
Impact

    A remote attacker could entice a user to open a specially crafted file
    (usually in a web browser), possibly leading to the execution of
    arbitrary code with the privileges of the user running the Adobe Flash
    Player. The attacker could also cause a user\'s machine to establish TCP
    sessions with arbitrary hosts, bypass the Security Sandbox Model,
    obtain sensitive information, port scan arbitrary hosts, or conduct
    cross-site-scripting attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-plugins/adobe-flash-9.0.115.0"
    Please be advised that unaffected packages of the Adobe Flash Player
    have known problems when used from within the Konqueror and Opera
    browsers.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4324');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4768');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5275');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6242');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6243');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6244');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6245');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6246');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-07] Adobe Flash Player: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Flash Player: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-plugins/adobe-flash", unaffected: make_list("ge 9.0.115.0"), vulnerable: make_list("lt 9.0.115.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
