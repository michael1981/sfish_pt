# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-02.xml
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
 script_id(36085);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-02");
 script_cve_id("CVE-2008-4316");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-02
(GLib: Execution of arbitrary code)


    Diego E. Petteno` reported multiple integer overflows in glib/gbase64.c
    when converting a long string from or to a base64 representation.
  
Impact

    A remote attacker could entice a user or automated system to perform a
    base64 conversion via an application using GLib, possibly resulting in
    the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GLib 2.18 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/glib-2.18.4-r1"
    All GLib 2.16 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/glib-2.16.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4316');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-02] GLib: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GLib: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/glib", unaffected: make_list("ge 2.18.4-r1", "rge 2.16.6-r1", "lt 2"), vulnerable: make_list("lt 2.18.4-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
