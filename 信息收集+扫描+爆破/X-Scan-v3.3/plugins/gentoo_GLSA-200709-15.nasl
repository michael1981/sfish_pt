# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-15.xml
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
 script_id(26117);
 script_version("$Revision: 1.9 $");
 script_xref(name: "GLSA", value: "200709-15");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-15
(BEA JRockit: Multiple vulnerabilities)


    An integer overflow vulnerability exists in the embedded ICC profile
    image parser (CVE-2007-2788), an unspecified vulnerability exists in
    the font parsing implementation (CVE-2007-4381), and an error exists
    when processing XSLT stylesheets contained in XSLT Transforms in XML
    signatures (CVE-2007-3716), among other vulnerabilities.
  
Impact

    A remote attacker could trigger the integer overflow to execute
    arbitrary code or crash the JVM through a specially crafted file. Also,
    an attacker could perform unauthorized actions via an applet that
    grants certain privileges to itself because of the font parsing
    vulnerability. The error when processing XSLT stylesheets can be
    exploited to execute arbitrary code. Other vulnerabilities could lead
    to establishing restricted network connections to certain services,
    Cross Site Scripting and Denial of Service attacks.
  
Workaround

    There is no known workaround at this time for all these
    vulnerabilities.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2788
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2789
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3004
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3005
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3503
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3698
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3716
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3922
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4381

');
script_set_attribute(attribute:'solution', value: '
    All BEA JRockit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/jrockit-jdk-bin-1.5.0.11_p1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-15.xml');
script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-15] BEA JRockit: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3503", "CVE-2007-3698", "CVE-2007-3716", "CVE-2007-3922", "CVE-2007-4381");
 script_summary(english: 'BEA JRockit: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/jrockit-jdk-bin", unaffected: make_list("ge 1.5.0.11_p1"), vulnerable: make_list("lt 1.5.0.11_p1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
