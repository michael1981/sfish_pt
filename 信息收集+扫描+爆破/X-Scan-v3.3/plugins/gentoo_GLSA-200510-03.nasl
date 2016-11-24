# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-03.xml
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
 script_id(19849);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200510-03");
 script_cve_id("CVE-2005-3149");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-03
(Uim: Privilege escalation vulnerability)


    Masanari Yamamoto discovered that Uim uses environment variables
    incorrectly. This bug causes a privilege escalation if setuid/setgid
    applications are linked to libuim. This bug only affects
    immodule-enabled Qt (if you build Qt 3.3.2 or later versions with
    USE="immqt" or USE="immqt-bc").
  
Impact

    A malicious local user could exploit this vulnerability to execute
    arbitrary code with escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Uim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-i18n/uim-0.4.9.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://lists.freedesktop.org/pipermail/uim/2005-September/001346.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3149');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-03] Uim: Privilege escalation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Uim: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-i18n/uim", unaffected: make_list("ge 0.4.9.1"), vulnerable: make_list("lt 0.4.9.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
