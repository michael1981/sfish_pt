# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-17.xml
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
 script_id(14550);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-17");
 script_cve_id("CVE-2004-0649");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-17
(l2tpd: Buffer overflow)


    Thomas Walpuski discovered a buffer overflow that may be exploitable by
    sending a specially crafted packet. In order to exploit the vulnerable
    code, an attacker would need to fake the establishment of an L2TP tunnel.
  
Impact

    A remote attacker may be able to execute arbitrary code with the privileges
    of the user running l2tpd.
  
Workaround

    There is no known workaround for this vulnerability.
  
');
script_set_attribute(attribute:'solution', value: '
    All users are recommended to upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-l2tpd-0.69-r2"
    # emerge ">=net-l2tpd-0.69-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0649');
script_set_attribute(attribute: 'see_also', value: 'http://seclists.org/lists/fulldisclosure/2004/Jun/0094.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-17] l2tpd: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'l2tpd: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dialup/l2tpd", unaffected: make_list("ge 0.69-r2"), vulnerable: make_list("lt 0.69-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
