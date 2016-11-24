# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-28.xml
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
 script_id(15776);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200411-28");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-28
(X.Org, XFree86: libXpm vulnerabilities)


    Several issues were discovered in libXpm, including integer
    overflows, out-of-bounds memory accesses, insecure path traversal and
    an endless loop.
  
Impact

    An attacker could craft a malicious pixmap file and entice a user
    to use it with an application linked against libXpm. This could lead to
    Denial of Service or arbitrary code execution.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All X.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-x11-6.7.0-r3"
    All XFree86 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xfree-x11-4.3.0-r8"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0914');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-28] X.Org, XFree86: libXpm vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org, XFree86: libXpm vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 6.8.0-r3", "rge 6.7.0-r3"), vulnerable: make_list("lt 6.8.0-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-base/xfree", unaffected: make_list("ge 4.3.0-r8"), vulnerable: make_list("lt 4.3.0-r8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
