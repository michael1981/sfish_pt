# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-17.xml
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
 script_id(14725);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-17");
 script_cve_id("CVE-2004-1469");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-17
(SUS: Local root vulnerability)


    Leon Juranic found a bug in the logging functionality of SUS that can
    lead to local privilege escalation. A format string vulnerability
    exists in the log() function due to an incorrect call to the syslog()
    function.
  
Impact

    An attacker with local user privileges can potentially exploit this
    vulnerability to gain root access.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SUS users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-admin/sus-2.0.2-r1"
    # emerge ">=app-admin/sus-2.0.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://pdg.uow.edu.au/sus/CHANGES');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/375109/2004-09-11/2004-09-17/0');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1469');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-17] SUS: Local root vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SUS: Local root vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/sus", unaffected: make_list("ge 2.0.2-r1"), vulnerable: make_list("lt 2.0.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
