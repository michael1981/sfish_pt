# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-26.xml
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
 script_id(27558);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-26");
 script_cve_id("CVE-2007-5208");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-26
(HPLIP: Privilege escalation)


    Kees Cook from the Ubuntu Security team discovered that the hpssd
    daemon does not correctly validate user supplied data before passing it
    to a "popen3()" call.
  
Impact

    A local attacker may be able to exploit this vulnerability by sending a
    specially crafted request to the hpssd daemon to execute arbitrary
    commands with the privileges of the user running hpssd, usually root.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All HPLIP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "net-print/hplip"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5208');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-26] HPLIP: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'HPLIP: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/hplip", unaffected: make_list("rge 1.7.4a-r2", "ge 2.7.9-r1"), vulnerable: make_list("lt 2.7.9-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
