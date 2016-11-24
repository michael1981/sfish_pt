# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-20.xml
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
 script_id(25341);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200705-20");
 script_cve_id("CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-20
(Blackdown Java: Applet privilege escalation)


    Chris Evans has discovered multiple buffer overflows in the Sun JDK and
    the Sun JRE possibly related to various AWT and font layout functions.
    Tom Hawtin has discovered an unspecified vulnerability in the Sun JDK
    and the Sun JRE relating to unintended applet data access. He has also
    discovered multiple other unspecified vulnerabilities in the Sun JDK
    and the Sun JRE allowing unintended Java applet or application resource
    acquisition. Additionally, a memory corruption error has been found in
    the handling of GIF images with zero width field blocks.
  
Impact

    An attacker could entice a user to run a specially crafted Java applet
    or application that could read, write, or execute local files with the
    privileges of the user running the JVM, access data maintained in other
    Java applets, or escalate the privileges of the currently running Java
    applet or application allowing for unauthorized access to system
    resources.
  
Workaround

    Disable the "nsplugin" USE flag in order to prevent web applets from
    being run.
  
');
script_set_attribute(attribute:'solution', value: '
    Since there is no fixed update from Blackdown and since the flaw only
    occurs in the applets, the "nsplugin" USE flag has been masked in the
    portage tree. Emerge the ebuild again in order to fix the
    vulnerability. Another solution is to switch to another Java
    implementation such as the Sun implementation (dev-java/sun-jdk and
    dev-java/sun-jre-bin).
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-java/blackdown-jdk"
    # emerge --ask --oneshot --verbose "dev-java/blackdown-jre"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6731');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6736');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6737');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6745');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-20] Blackdown Java: Applet privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Blackdown Java: Applet privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/blackdown-jre", unaffected: make_list("ge 1.4.2.03-r14"), vulnerable: make_list("lt 1.4.2.03-r14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/blackdown-jdk", unaffected: make_list("ge 1.4.2.03-r14"), vulnerable: make_list("lt 1.4.2.03-r14")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
