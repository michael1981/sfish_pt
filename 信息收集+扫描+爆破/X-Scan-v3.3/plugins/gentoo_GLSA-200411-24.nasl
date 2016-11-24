# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-24.xml
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
 script_id(15725);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200411-24");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-24
(BNC: Buffer overflow vulnerability)


    Leon Juranic discovered that BNC fails to do proper bounds
    checking when checking server response.
  
Impact

    An attacker could exploit this to cause a Denial of Service and
    potentially execute arbitary code with the permissions of the user
    running BNC.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All BNC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/bnc-2.9.1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://gotbnc.com/changes.html');
script_set_attribute(attribute: 'see_also', value: 'http://security.lss.hr/en/index.php?page=details&ID=LSS-2004-11-03');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-24] BNC: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BNC: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/bnc", unaffected: make_list("ge 2.9.1"), vulnerable: make_list("lt 2.9.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
