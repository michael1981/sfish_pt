# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-15.xml
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
 script_id(40962);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200909-15");
 script_cve_id("CVE-2005-2929", "CVE-2008-4690");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-15
(Lynx: Arbitrary command execution)


    Clint Ruoho reported that the fix for CVE-2005-2929 (GLSA 200511-09)
    only disabled the lynxcgi:// handler when not using the advanced mode.
  
Impact

    A remote attacker can entice a user to access a malicious HTTP server,
    causing Lynx to execute arbitrary commands. NOTE: The advanced mode is
    not enabled by default. Successful exploitation requires the
    "lynxcgi://" protocol to be registered with lynx on the victim\'s
    system.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Lynx users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-client/lynx-2.8.6-r4
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2929');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4690');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-09.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-15] Lynx: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Lynx: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/lynx", unaffected: make_list("ge 2.8.6-r4"), vulnerable: make_list("lt 2.8.6-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
