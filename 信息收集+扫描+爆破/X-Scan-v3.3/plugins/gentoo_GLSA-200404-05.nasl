# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-05.xml
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
 script_id(14470);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200404-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-05
(ipsec-tools contains an X.509 certificates vulnerability.)


    racoon (a utility in the ipsec-tools package) does not verify digital
    signatures on Phase1 packets.  This means  that anybody holding the correct
    X.509 certificate would be able to establish a connection, even if they did
    not have the corresponding private key.
  
Impact

    Since digital signatures are not verified by the racoon tool, an attacker may
	be able to connect to the VPN gateway and/or execute a man-in-the-middle attack.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    ipsec-tools users should upgrade to version 0.2.5 or later:
    # emerge sync
    # emerge -pv ">=net-firewall/ipsec-tools-0.2.5"
    # emerge ">=net-firewall/ipsec-tools-0.2.5"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-05] ipsec-tools contains an X.509 certificates vulnerability.');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ipsec-tools contains an X.509 certificates vulnerability.');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/ipsec-tools", arch: "amd64", unaffected: make_list("ge 0.2.5"), vulnerable: make_list("le 0.2.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
