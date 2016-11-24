# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-09.xml
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
 script_id(15447);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200410-09");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-09
(LessTif: Integer and stack overflows in libXpm)


    Chris Evans has discovered various integer and stack overflows in libXpm,
    which is shipped as a part of the X Window System. LessTif, an application
    that includes this library, is susceptible to the same issues.
  
Impact

    A carefully-crafted XPM file could crash applications that are linked
    against libXpm, such as LessTif, potentially allowing the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LessTif users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-libs/lesstif-0.93.97"
    # emerge ">=x11-libs/lesstif-0.93.97"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0687');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0688');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-34.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.lesstif.org/ReleaseNotes.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-09] LessTif: Integer and stack overflows in libXpm');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LessTif: Integer and stack overflows in libXpm');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/lesstif", unaffected: make_list("ge 0.93.97"), vulnerable: make_list("lt 0.93.97")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
