# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-06.xml
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
 script_id(20315);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-06");
 script_cve_id("CVE-2005-3651");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-06
(Ethereal: Buffer overflow in OSPF protocol dissector)


    iDEFENSE reported a possible overflow due to the lack of bounds
    checking in the dissect_ospf_v3_address_prefix() function, part of the
    OSPF protocol dissector.
  
Impact

    An attacker might be able to craft a malicious network flow that
    would crash Ethereal. It may be possible, though unlikely, to exploit
    this flaw to execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.13-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3651');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=349&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-06] Ethereal: Buffer overflow in OSPF protocol dissector');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Buffer overflow in OSPF protocol dissector');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.13-r2"), vulnerable: make_list("lt 0.10.13-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
