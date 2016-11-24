# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-03.xml
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
 script_id(29290);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200712-03");
 script_cve_id("CVE-2007-5795", "CVE-2007-6109");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-03
(GNU Emacs: Multiple vulnerabilities)


    Drake Wilson reported that the hack-local-variables() function in GNU
    Emacs 22 does not properly match assignments of local variables in a
    file against a list of unsafe or risky variables, allowing to override
    them (CVE-2007-5795). Andreas Schwab (SUSE) discovered a stack-based
    buffer overflow in the format function when handling values with high
    precision (CVE-2007-6109).
  
Impact

    Remote attackers could entice a user to open a specially crafted file
    in GNU Emacs, possibly leading to the execution of arbitrary Emacs Lisp
    code (via CVE-2007-5795) or arbitrary code (via CVE-2007-6109) with the
    privileges of the user running GNU Emacs.
  
Workaround

    The first vulnerability can be worked around by setting the
    "enable-local-variables" option to "nil", disabling the processing of
    local variable lists. GNU Emacs prior to version 22 is not affected by
    this vulnerability. There is no known workaround for the second
    vulnerability at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Emacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/emacs-22.1-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5795');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6109');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-03] GNU Emacs: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU Emacs: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-editors/emacs", unaffected: make_list("ge 22.1-r3", "rge 21.4-r14", "lt 19"), vulnerable: make_list("lt 22.1-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
