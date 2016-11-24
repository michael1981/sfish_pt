# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-06.xml
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
 script_id(35350);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200901-06");
 script_cve_id("CVE-2006-2236");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-06
(Tremulous: User-assisted execution of arbitrary code)


    It has been reported that Tremulous includes a vulnerable version of
    the ioQuake3 engine (GLSA 200605-12, CVE-2006-2236).
  
Impact

    A remote attacker could entice a user to connect to a malicious games
    server, possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Tremulous users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/tremulous-1.1.0-r2"
    Note: The binary version of Tremulous has been removed from the Portage
    tree.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2236');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-12.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-06] Tremulous: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tremulous: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-fps/tremulous", unaffected: make_list("ge 1.1.0-r2"), vulnerable: make_list("lt 1.1.0-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "games-fps/tremulous-bin", unaffected: make_list(), vulnerable: make_list("lt 1.1.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
