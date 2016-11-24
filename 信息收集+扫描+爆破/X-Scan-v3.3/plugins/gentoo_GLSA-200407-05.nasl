# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-05.xml
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
 script_id(14538);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200407-05");
 script_cve_id("CVE-2004-0419");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-05
(XFree86, X.org: XDM ignores requestPort setting)


    XDM will open TCP sockets for its chooser, even if the
    DisplayManager.requestPort setting is set to 0. Remote clients can use this
    port to connect to XDM and request a login window, thus allowing access to
    the system.
  
Impact

    Authorized users may be able to login remotely to a machine running XDM,
    even if this option is disabled in XDM\'s configuration. Please note that an
    attacker must have a preexisting account on the machine in order to exploit
    this vulnerability.
  
Workaround

    There is no known workaround at this time. All users should upgrade to the
    latest available version of X.
  
');
script_set_attribute(attribute:'solution', value: '
    If you are using XFree86, you should run the following:
    # emerge sync
    # emerge -pv ">=x11-base/xfree-4.3.0-r6"
    # emerge ">=x11-base/xfree-4.3.0-r6"
    If you are using X.org\'s X11 server, you should run the following:
    # emerge sync
    # emerge -pv ">=x11-base/xorg-x11-6.7.0-r1"
    # emerge ">=x11-base/xorg-x11-6.7.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0419');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.xfree86.org/show_bug.cgi?id=1376');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-05] XFree86, X.org: XDM ignores requestPort setting');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XFree86, X.org: XDM ignores requestPort setting');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 6.7.0-r1"), vulnerable: make_list("le 6.7.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-base/xfree", unaffected: make_list("ge 4.3.0-r6"), vulnerable: make_list("le 4.3.0-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
