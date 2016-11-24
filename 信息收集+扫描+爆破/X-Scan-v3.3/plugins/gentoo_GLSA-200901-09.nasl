# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-09.xml
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
 script_id(35367);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200901-09");
 script_cve_id("CVE-2008-2549", "CVE-2008-2992", "CVE-2008-4812", "CVE-2008-4813", "CVE-2008-4814", "CVE-2008-4815", "CVE-2008-4817");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-09
(Adobe Reader: User-assisted execution of arbitrary code)


    An unspecified vulnerability can be triggered by a malformed PDF
    document, as demonstrated by 2008-HI2.pdf (CVE-2008-2549).
    Peter Vreugdenhil, Dyon Balding, Will Dormann, Damian Frizza, and Greg
    MacManus reported a stack-based buffer overflow in the util.printf
    JavaScript function that incorrectly handles the format string argument
    (CVE-2008-2992).
    Greg MacManus of iDefense Labs reported an array index error that can
    be leveraged for an out-of-bounds write, related to parsing of Type 1
    fonts (CVE-2008-4812).
    Javier Vicente Vallejo and Peter Vregdenhil, via Zero Day Initiative,
    reported multiple unspecified memory corruption vulnerabilities
    (CVE-2008-4813).
    Thomas Garnier of SkyRecon Systems reported an unspecified
    vulnerability in a JavaScript method, related to an "input validation
    issue" (CVE-2008-4814).
    Josh Bressers of Red Hat reported an untrusted search path
    vulnerability (CVE-2008-4815).
    Peter Vreugdenhil reported through iDefense that the Download Manager
    can trigger a heap corruption via calls to the AcroJS function
    (CVE-2008-4817).
  
Impact

    A remote attacker could entice a user to open a specially crafted PDF
    document, and local attackers could entice a user to run acroread from
    an untrusted working directory. Both might result in the execution of
    arbitrary code with the privileges of the user running the application,
    or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-8.1.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2549');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2992');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4812');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4813');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4814');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4815');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4817');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-09] Adobe Reader: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Reader: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 8.1.3"), vulnerable: make_list("lt 8.1.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
