# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-31.xml
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
 script_id(17234);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-31");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-31 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-31
(uim: Privilege escalation vulnerability)


    Takumi Asaki discovered that uim insufficiently checks environment
    variables. setuid/setgid applications linked against libuim could end
    up executing arbitrary code. This vulnerability only affects
    immodule-enabled Qt (if you build Qt 3.3.2 or later versions with
    USE="immqt" or USE="immqt-bc").
  
Impact

    A malicious local user could exploit this vulnerability to execute
    arbitrary code with escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All uim users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-i18n/uim-0.4.5.1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0503');
script_set_attribute(attribute: 'see_also', value: 'http://lists.freedesktop.org/archives/uim/2005-February/000996.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-31.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-31] uim: Privilege escalation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'uim: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-i18n/uim", unaffected: make_list("ge 0.4.5.1"), vulnerable: make_list("lt 0.4.5.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
