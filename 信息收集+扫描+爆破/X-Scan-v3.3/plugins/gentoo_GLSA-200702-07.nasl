# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-07.xml
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
 script_id(24368);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200702-07");
 script_cve_id("CVE-2007-0243");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-07
(Sun JDK/JRE: Execution of arbitrary code)


    A anonymous researcher discovered that an error in the handling of a
    GIF image with a zero width field block leads to a memory corruption
    flaw.
  
Impact

    An attacker could entice a user to run a specially crafted Java applet
    or application that would load a crafted GIF image, which could result
    in escalation of privileges and unauthorized access to system
    resources.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sun Java Development Kit 1.5 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.5.0.10"
    All Sun Java Development Kit 1.4 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "=dev-java/sun-jdk-1.4.2*"
    All Sun Java Runtime Environment 1.5 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.5.0.10"
    All Sun Java Runtime Environment 1.4 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "=dev-java/sun-jre-bin-1.4.2*"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0243');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-07] Sun JDK/JRE: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun JDK/JRE: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.5.0.10", "rge 1.4.2.18", "rge 1.4.2.17", "rge 1.4.2.15", "rge 1.4.2.14", "rge 1.4.2.13"), vulnerable: make_list("lt 1.5.0.10", "lt 1.4.2.13")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.5.0.10", "rge 1.4.2.18", "rge 1.4.2.17", "rge 1.4.2.15", "rge 1.4.2.14", "rge 1.4.2.13"), vulnerable: make_list("lt 1.5.0.10", "lt 1.4.2.13")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
