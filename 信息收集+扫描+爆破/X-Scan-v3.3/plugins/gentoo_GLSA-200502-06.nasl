# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-06.xml
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
 script_id(16443);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-06");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-06
(LessTif: Multiple vulnerabilities in libXpm)


    Multiple vulnerabilities, including buffer overflows, out of
    bounds memory access and directory traversals, have been discovered in
    libXpm, which is shipped as a part of the X Window System. LessTif, an
    application that includes libXpm, suffers from the same issues.
  
Impact

    A carefully-crafted XPM file could crash applications making use
    of the LessTif toolkit, potentially allowing the execution of arbitrary
    code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LessTif users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/lesstif-0.94.0"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0914');
script_set_attribute(attribute: 'see_also', value: 'http://www.lesstif.org/ReleaseNotes.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-06] LessTif: Multiple vulnerabilities in libXpm');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LessTif: Multiple vulnerabilities in libXpm');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/lesstif", unaffected: make_list("ge 0.94.0"), vulnerable: make_list("lt 0.94.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
