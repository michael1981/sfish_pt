# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-07.xml
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
 script_id(14458);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200403-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-07
(Multiple remote overflows and vulnerabilities in Ethereal)


    There are multiple vulnerabilities in versions of Ethereal earlier than 0.10.3, including:
	Thirteen buffer overflows in the following protocol dissectors: NetFlow, IGAP, EIGRP, PGM, IrDA, BGP, ISUP, and TCAP.
      	A zero-length Presentation protocol selector could make Ethereal crash.
     	A vulnerability in the RADIUS packet dissector which may crash ethereal.
      	A corrupt color filter file could cause a segmentation fault.
  
Impact

    These vulnerabilities may cause Ethereal to crash or may allow an attacker
    to run arbitrary code on the user\'s computer.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the current version of the affected package:
    # emerge sync
    # emerge -pv ">=net-analyzer/ethereal-0.10.3"
    # emerge ">=net-analyzer/ethereal-0.10.3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/appnotes/enpa-sa-00013.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0176');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0365');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0367');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-07] Multiple remote overflows and vulnerabilities in Ethereal');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple remote overflows and vulnerabilities in Ethereal');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.3"), vulnerable: make_list("le 0.10.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
