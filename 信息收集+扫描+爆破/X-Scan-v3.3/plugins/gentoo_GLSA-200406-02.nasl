# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-02.xml
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
 script_id(14513);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200406-02");
 script_cve_id("CVE-2004-0536");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-02
(tripwire: Format string vulnerability)


    The code that generates email reports contains a format string
    vulnerability in pipedmailmessage.cpp.
  
Impact

    With a carefully crafted filename on a local filesystem an attacker
    could cause execution of arbitrary code with permissions of the user
    running tripwire, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All tripwire users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-admin/tripwire-2.3.1.2-r1"
    # emerge ">=app-admin/tripwire-2.3.1.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/365036/2004-05-31/2004-06-06/0');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0536');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-02] tripwire: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'tripwire: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/tripwire", unaffected: make_list("ge 2.3.1.2-r1"), vulnerable: make_list("le 2.3.1.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
