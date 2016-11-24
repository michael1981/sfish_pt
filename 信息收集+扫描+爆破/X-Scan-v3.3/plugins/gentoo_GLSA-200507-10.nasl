# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-10.xml
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
 script_id(18669);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-10
(Ruby: Arbitrary command execution through XML-RPC)


    Nobuhiro IMAI reported that an invalid default value in "utils.rb"
    causes the security protections of the XML-RPC server to fail.
  
Impact

    A remote attacker could exploit this vulnerability to execute
    arbitrary commands.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ruby users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.8.2-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1992');
script_set_attribute(attribute: 'see_also', value: 'http://www.ruby-lang.org/en/20050701.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-10] Ruby: Arbitrary command execution through XML-RPC');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: Arbitrary command execution through XML-RPC');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("ge 1.8.2-r2"), vulnerable: make_list("lt 1.8.2-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
