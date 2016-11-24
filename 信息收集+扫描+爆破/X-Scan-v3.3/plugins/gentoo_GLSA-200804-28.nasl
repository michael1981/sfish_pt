# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-28.xml
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
 script_id(32074);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200804-28");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-28
(JRockit: Multiple vulnerabilities)


    Because of sharing the same codebase, JRockit is affected by the
    vulnerabilities mentioned in GLSA 200804-20.
  
Impact

    A remote attacker could entice a user to run a specially crafted applet
    on a website or start an application in Java Web Start to execute
    arbitrary code outside of the Java sandbox and of the Java security
    restrictions with the privileges of the user running Java. The attacker
    could also obtain sensitive information, create, modify, rename and
    read local files, execute local applications, establish connections in
    the local network, bypass the same origin policy, and cause a Denial of
    Service via multiple vectors.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All JRockit 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/jrockit-jdk-bin-1.4.2.16"
    All JRockit 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/jrockit-jdk-bin-1.5.0.14"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-20.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-28] JRockit: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'JRockit: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/jrockit-jdk-bin", unaffected: make_list("rge 1.4.2.16", "ge 1.5.0.14"), vulnerable: make_list("lt 1.5.0.14")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
