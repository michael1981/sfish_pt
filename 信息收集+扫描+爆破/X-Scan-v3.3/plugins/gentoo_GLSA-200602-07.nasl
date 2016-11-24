# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-07.xml
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
 script_id(20921);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200602-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200602-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200602-07
(Sun JDK/JRE: Applet privilege escalation)


    Applets executed using JRE or JDK can use "reflection" APIs
    functions to elevate its privileges beyond the sandbox restrictions.
    Adam Gowdiak discovered five vulnerabilities that use this method for
    privilege escalation. Two more vulnerabilities were discovered by the
    vendor. Peter Csepely discovered that Web Start Java applications also
    can an escalate their privileges.
  
Impact

    A malicious Java applet can bypass Java sandbox restrictions and
    hence access local files, connect to arbitrary network locations and
    execute arbitrary code on the user\'s machine. Java Web Start
    applications are affected likewise.
  
Workaround

    Select another Java implementation using java-config.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.10"
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.10"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://sunsolve.sun.com/search/document.do?assetkey=1-26-102170-1');
script_set_attribute(attribute: 'see_also', value: 'http://sunsolve.sun.com/search/document.do?assetkey=1-26-102171-1');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0614');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0615');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0616');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0617');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200602-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200602-07] Sun JDK/JRE: Applet privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun JDK/JRE: Applet privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.4.2.10"), vulnerable: make_list("lt 1.4.2.10")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.4.2.10"), vulnerable: make_list("lt 1.4.2.10")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
