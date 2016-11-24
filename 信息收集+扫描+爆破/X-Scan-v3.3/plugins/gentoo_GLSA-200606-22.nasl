# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-22.xml
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
 script_id(21742);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200606-22");
 script_cve_id("CVE-2006-2916");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-22
(aRts: Privilege escalation)


    artswrapper fails to properly check whether it can drop privileges
    accordingly if setuid() fails due to a user exceeding assigned resource
    limits.
  
Impact

    Local attackers could exploit this vulnerability to execute arbitrary
    code with elevated privileges. Note that the aRts package provided by
    Gentoo is only vulnerable if the artswrappersuid USE-flag is enabled.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All aRts users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/arts
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2916');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-22] aRts: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'aRts: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/arts", unaffected: make_list("ge 3.5.2-r1", "rge 3.4.3-r1"), vulnerable: make_list("lt 3.5.2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
