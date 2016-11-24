# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-01.xml
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
 script_id(35345);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200901-01");
 script_cve_id("CVE-2008-4395");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-01
(NDISwrapper: Arbitrary remote code execution)


    Anders Kaseorg reported multiple buffer overflows related to long
    ESSIDs.
  
Impact

    A physically proximate attacker could send packets over a wireless
    network that might lead to the execution of arbitrary code with root
    privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All NDISwrapper users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/ndiswrapper-1.53-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4395');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-01] NDISwrapper: Arbitrary remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NDISwrapper: Arbitrary remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/ndiswrapper", unaffected: make_list("ge 1.53-r1"), vulnerable: make_list("lt 1.53-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
