# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-20.xml
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
 script_id(16471);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-20");
 script_cve_id("CVE-2005-0100");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-20
(Emacs, XEmacs: Format string vulnerabilities in movemail)


    Max Vozeler discovered that the movemail utility contains several
    format string errors.
  
Impact

    An attacker could set up a malicious POP server and entice a user to
    connect to it using movemail, resulting in the execution of arbitrary
    code with the rights of the victim user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Emacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/emacs-21.4"
    All XEmacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/xemacs-21.4.15-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0100');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-20] Emacs, XEmacs: Format string vulnerabilities in movemail');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Emacs, XEmacs: Format string vulnerabilities in movemail');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-editors/xemacs", unaffected: make_list("ge 21.4.15-r3"), vulnerable: make_list("lt 21.4.15-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-editors/emacs", unaffected: make_list("ge 21.4", "lt 19"), vulnerable: make_list("lt 21.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
