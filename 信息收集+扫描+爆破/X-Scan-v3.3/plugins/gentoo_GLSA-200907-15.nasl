# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-15.xml
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
 script_id(39869);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200907-15");
 script_cve_id("CVE-2008-5027", "CVE-2008-5028", "CVE-2008-6373", "CVE-2009-2288");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-15
(Nagios: Execution of arbitrary code)


    Multiple vulnerabilities have been reported in Nagios:
    Paul reported that statuswml.cgi does not properly sanitize shell
    metacharacters in the (1) ping and (2) traceroute parameters
    (CVE-2009-2288).
    Nagios does not properly verify whether an authenticated user is
    authorized to run certain commands (CVE-2008-5027).
    Andreas Ericsson reported that Nagios does not perform validity checks
    to verify HTTP requests, leading to Cross-Site Request Forgery
    (CVE-2008-5028).
    An unspecified vulnerability in Nagios related to CGI programs,
    "adaptive external commands," and "writing newlines and submitting
    service comments" has been reported (CVE-2008-6373).
  
Impact

    A remote authenticated or unauthenticated attacker may exploit these
    vulnerabilities to execute arbitrary commands or elevate privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Nagios users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/nagios-core-3.0.6-r2"
    NOTE: Users of the Nagios 2 branch can update to version 2.12-r1 which
    contains a patch to fix CVE-2009-2288. However, that branch is not
    supported upstream or in Gentoo and we are unaware whether the other
    vulnerabilities affect 2.x installations.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5027');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5028');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6373');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2288');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-15] Nagios: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Nagios: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/nagios-core", unaffected: make_list("ge 3.0.6-r2"), vulnerable: make_list("lt 3.0.6-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
