# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200902-06.xml
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
 script_id(35732);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200902-06");
 script_cve_id("CVE-2008-2142", "CVE-2008-3949");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200902-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200902-06
(GNU Emacs, XEmacs: Multiple vulnerabilities)


    Morten Welinder reports about GNU Emacs and edit-utils in XEmacs: By
    shipping a .flc accompanying a source file (.c for example) and setting
    font-lock-support-mode to fast-lock-mode in the source file through
    local variables, any Lisp code in the .flc file is executed without
    warning (CVE-2008-2142).
    Romain Francoise reported a security risk in a feature of GNU Emacs
    related to interacting with Python. The vulnerability arises because
    Python, by default, prepends the current directory to the module search
    path, allowing for arbitrary code execution when launched from a
    specially crafted directory (CVE-2008-3949).
  
Impact

    Remote attackers could entice a user to open a specially crafted file
    in GNU Emacs, possibly leading to the execution of arbitrary Emacs Lisp
    code or arbitrary Python code with the privileges of the user running
    GNU Emacs or XEmacs.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Emacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/emacs-22.2-r3"
    All edit-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-xemacs/edit-utils-2.39"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2142');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3949');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200902-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200902-06] GNU Emacs, XEmacs: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU Emacs, XEmacs: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-xemacs/edit-utils", unaffected: make_list("ge 2.39"), vulnerable: make_list("lt 2.39")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-editors/emacs", unaffected: make_list("ge 22.2-r3", "rge 21.4-r17", "lt 19"), vulnerable: make_list("lt 22.2-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
