# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200902-03.xml
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
 script_id(35674);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200902-03");
 script_cve_id("CVE-2008-4865");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200902-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200902-03
(Valgrind: Untrusted search path)


    Tavis Ormandy reported that Valgrind loads a .valgrindrc file in the
    current working directory, executing commands specified there.
  
Impact

    A local attacker could prepare a specially crafted .valgrindrc file and
    entice a user to run Valgrind from the directory containing that file,
    resulting in the execution of arbitrary code with the privileges of the
    user running Valgrind.
  
Workaround

    Do not run "valgrind" from untrusted working directories.
  
');
script_set_attribute(attribute:'solution', value: '
    All Valgrind users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/valgrind-3.4.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4865');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200902-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200902-03] Valgrind: Untrusted search path');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Valgrind: Untrusted search path');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/valgrind", unaffected: make_list("ge 3.4.0"), vulnerable: make_list("lt 3.4.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
