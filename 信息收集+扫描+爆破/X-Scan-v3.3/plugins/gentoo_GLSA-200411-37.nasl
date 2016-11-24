# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-37.xml
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
 script_id(15843);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200411-37");
 script_cve_id("CVE-2004-1127");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-37 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-37
(Open DC Hub: Remote code execution)


    Donato Ferrante discovered a buffer overflow vulnerability in the
    RedirectAll command of the Open DC Hub.
  
Impact

    Upon exploitation, a remote user with administrative privileges can
    execute arbitrary code on the system running the Open DC Hub.
  
Workaround

    Only give administrative rights to trusted users.
  
');
script_set_attribute(attribute:'solution', value: '
    All Open DC Hub users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/opendchub-0.7.14-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2004-11/1115.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1127');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-37.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-37] Open DC Hub: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Open DC Hub: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/opendchub", unaffected: make_list("ge 0.7.14-r2"), vulnerable: make_list("lt 0.7.14-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
