# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200911-02.xml
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
 script_id(42834);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200911-02");
 script_cve_id("CVE-2008-2086", "CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3109", "CVE-2008-3110", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114", "CVE-2008-3115", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5355", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107", "CVE-2009-2409", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2689", "CVE-2009-2690", "CVE-2009-2716", "CVE-2009-2718", "CVE-2009-2719", "CVE-2009-2720", "CVE-2009-2721", "CVE-2009-2722", "CVE-2009-2723", "CVE-2009-2724", "CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3886");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200911-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200911-02
(Sun JDK/JRE: Multiple vulnerabilites)


    Multiple vulnerabilites have been reported in the Sun Java
    implementation. Please review the CVE identifiers referenced below and
    the associated Sun Alerts for details.
  
Impact

    A remote attacker could entice a user to open a specially crafted JAR
    archive, applet, or Java Web Start application, possibly resulting in
    the execution of arbitrary code with the privileges of the user running
    the application. Furthermore, a remote attacker could cause a Denial of
    Service affecting multiple services via several vectors, disclose
    information and memory contents, write or execute local files, conduct
    session hijacking attacks via GIFAR files, steal cookies, bypass the
    same-origin policy, load untrusted JAR files, establish network
    connections to arbitrary hosts and posts via several vectors, modify
    the list of supported graphics configurations, bypass HMAC-based
    authentication systems, escalate privileges via several vectors and
    cause applet code to be executed with older, possibly vulnerable
    versions of the JRE.
    NOTE: Some vulnerabilities require a trusted environment, user
    interaction, a DNS Man-in-the-Middle or Cross-Site-Scripting attack.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sun JRE 1.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-java/sun-jre-bin-1.5.0.22
    All Sun JRE 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-java/sun-jre-bin-1.6.0.17
    All Sun JDK 1.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-java/sun-jdk-1.5.0.22
    All Sun JDK 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-java/sun-jdk-1.6.0.17
    All users of the precompiled 32bit Sun JRE 1.5.x should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =app-emulation/emul-linux-x86-java-1.5.0.22
    All users of the precompiled 32bit Sun JRE 1.6.x should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =app-emulation/emul-linux-x86-java-1.6.0.17
    All Sun JRE 1.4.x, Sun JDK 1.4.x, Blackdown JRE, Blackdown JDK and
    precompiled 32bit Sun JRE 1.4.x users are strongly advised to unmerge
    Java 1.4:
    # emerge --unmerge =app-emulation/emul-linux-x86-java-1.4*
    # emerge --unmerge =dev-java/sun-jre-bin-1.4*
    # emerge --unmerge =dev-java/sun-jdk-1.4*
    # emerge --unmerge dev-java/blackdown-jdk
    # emerge --unmerge dev-java/blackdown-jre
    Gentoo is ceasing support for the 1.4 generation of the Sun Java
    Platform in accordance with upstream. All 1.4 JRE and JDK versions are
    masked and will be removed shortly.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2086');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3103');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3104');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3105');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3106');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3107');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3108');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3109');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3110');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3111');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3112');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3113');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3114');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3115');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5339');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5340');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5341');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5342');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5343');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5344');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5345');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5346');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5347');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5348');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5349');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5350');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5351');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5352');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5353');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5354');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5355');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5356');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5357');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5358');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5359');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5360');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1093');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1094');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1095');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1096');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1097');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1098');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1099');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1100');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1101');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1102');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1103');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1104');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1105');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1106');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1107');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2409');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2475');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2476');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2670');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2671');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2672');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2673');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2674');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2675');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2676');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2689');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2690');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2716');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2718');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2719');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2720');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2721');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2722');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2723');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2724');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3728');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3729');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3865');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3866');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3867');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3868');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3869');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3871');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3872');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3873');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3874');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3875');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3876');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3877');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3879');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3880');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3881');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3882');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3883');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3884');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3886');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200911-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200911-02] Sun JDK/JRE: Multiple vulnerabilites');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun JDK/JRE: Multiple vulnerabilites');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/blackdown-jre", unaffected: make_list(), vulnerable: make_list("le 1.4.2.03-r14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable: make_list("lt 1.6.0.17")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable: make_list("lt 1.6.0.17")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-emulation/emul-linux-x86-java", unaffected: make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable: make_list("lt 1.6.0.17")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/blackdown-jdk", unaffected: make_list(), vulnerable: make_list("le 1.4.2.03-r16")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
