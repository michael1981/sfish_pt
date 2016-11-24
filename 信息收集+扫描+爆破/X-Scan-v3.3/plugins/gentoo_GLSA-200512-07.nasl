# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-07.xml
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
 script_id(20327);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200512-07");
 script_cve_id("CVE-2005-4442", "CVE-2005-4443");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-07
(OpenLDAP, Gauche: RUNPATH issues)


    Gentoo packaging for OpenLDAP and Gauche may introduce insecure paths
    into the list of directories that are searched for libraries at
    runtime.
  
Impact

    A local attacker, who is a member of the "portage" group, could create
    a malicious shared object in the Portage temporary build directory that
    would be loaded at runtime by a dependent binary, potentially resulting
    in privilege escalation.
  
Workaround

    Only grant "portage" group rights to trusted users.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenLDAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-nds/openldap
    All Gauche users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-scheme/gauche-0.8.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4442');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4443');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-07] OpenLDAP, Gauche: RUNPATH issues');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP, Gauche: RUNPATH issues');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-scheme/gauche", unaffected: make_list("ge 0.8.6-r1"), vulnerable: make_list("lt 0.8.6-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.2.28-r3", "rge 2.1.30-r6"), vulnerable: make_list("lt 2.2.28-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
