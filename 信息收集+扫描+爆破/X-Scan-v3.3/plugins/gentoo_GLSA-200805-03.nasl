# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-03.xml
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
 script_id(32151);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-03");
 script_cve_id("CVE-2008-1142", "CVE-2008-1692");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-03
(Multiple X11 terminals: Local privilege escalation)


    Bernhard R. Link discovered that RXVT opens a terminal on :0 if the
    "-display" option is not specified and the DISPLAY environment variable
    is not set. Further research by the Gentoo Security Team has shown that
    aterm, Eterm, Mrxvt, multi-aterm, rxvt-unicode, and wterm are also
    affected.
  
Impact

    A local attacker could exploit this vulnerability to hijack X11
    terminals of other users.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All aterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/aterm-1.0.1-r1"
    All Eterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/eterm-0.9.4-r1"
    All Mrxvt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/mrxvt-0.5.3-r2"
    All multi-aterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/multi-aterm-0.2.1-r1"
    All RXVT users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/rxvt-2.7.10-r4"
    All rxvt-unicode users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/rxvt-unicode-9.02-r1"
    All wterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/wterm-6.2.9-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1142');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1692');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-03] Multiple X11 terminals: Local privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple X11 terminals: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-terms/mrxvt", unaffected: make_list("ge 0.5.3-r2"), vulnerable: make_list("lt 0.5.3-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-terms/eterm", unaffected: make_list("ge 0.9.4-r1"), vulnerable: make_list("lt 0.9.4-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-terms/multi-aterm", unaffected: make_list("ge 0.2.1-r1"), vulnerable: make_list("lt 0.2.1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-terms/rxvt-unicode", unaffected: make_list("ge 9.02-r1"), vulnerable: make_list("lt 9.02-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-terms/aterm", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-terms/rxvt", unaffected: make_list("ge 2.7.10-r4"), vulnerable: make_list("lt 2.7.10-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-terms/wterm", unaffected: make_list("ge 6.2.9-r3"), vulnerable: make_list("lt 6.2.9-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
