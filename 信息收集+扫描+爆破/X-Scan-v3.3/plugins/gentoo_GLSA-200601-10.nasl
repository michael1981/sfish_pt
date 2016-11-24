# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-10.xml
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
 script_id(20731);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200601-10");
 script_cve_id("CVE-2005-3905", "CVE-2005-3906");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-10
(Sun and Blackdown Java: Applet privilege escalation)


    Adam Gowdiak discovered multiple vulnerabilities in the Java
    Runtime Environment\'s Reflection APIs that may allow untrusted applets
    to elevate privileges.
  
Impact

    A remote attacker could embed a malicious Java applet in a web
    page and entice a victim to view it. This applet can then bypass
    security restrictions and execute any command or access any file with
    the rights of the user running the web browser.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.09"
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.09"
    All Blackdown JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/blackdown-jdk-1.4.2.03"
    All Blackdown JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/blackdown-jre-1.4.2.03"
    Note to SPARC and PPC users: There is no stable secure
    Blackdown Java for the SPARC or PPC architectures. Affected users on
    the PPC architecture should consider switching to the IBM Java packages
    (ibm-jdk-bin and ibm-jre-bin). Affected users on the SPARC should
    remove the package until a SPARC package is released.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3905');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3906');
script_set_attribute(attribute: 'see_also', value: 'http://sunsolve.sun.com/searchproxy/document.do?assetkey=1-26-102003-1');
script_set_attribute(attribute: 'see_also', value: 'http://www.blackdown.org/java-linux/java2-status/security/Blackdown-SA-2005-03.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-10] Sun and Blackdown Java: Applet privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun and Blackdown Java: Applet privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/blackdown-jre", unaffected: make_list("ge 1.4.2.03"), vulnerable: make_list("lt 1.4.2.03")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.4.2.09"), vulnerable: make_list("lt 1.4.2.09")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.4.2.09"), vulnerable: make_list("lt 1.4.2.09")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/blackdown-jdk", unaffected: make_list("ge 1.4.2.03"), vulnerable: make_list("lt 1.4.2.03")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
