# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-09.xml
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
 script_id(20419);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200601-09");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-09
(Wine: Windows Metafile SETABORTPROC vulnerability)


    H D Moore discovered that Wine implements the insecure-by-design
    SETABORTPROC GDI Escape function for Windows Metafile (WMF) files.
  
Impact

    An attacker could entice a user to open a specially crafted Windows
    Metafile (WMF) file from within a Wine executed Windows application,
    possibly resulting in the execution of arbitrary code with the rights
    of the user running Wine.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/wine-0.9.0"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0106');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-09] Wine: Windows Metafile SETABORTPROC vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wine: Windows Metafile SETABORTPROC vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/wine", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 20060000", "gt 20040000")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
