# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-18.xml
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
 script_id(21711);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200606-18");
 script_cve_id("CVE-2005-4713", "CVE-2006-0056");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-18
(PAM-MySQL: Multiple vulnerabilities)


    A flaw in handling the result of pam_get_item() as well as further
    unspecified flaws were discovered in PAM-MySQL.
  
Impact

    By exploiting the mentioned flaws an attacker can cause a Denial of
    Service and thus prevent users that authenticate against PAM-MySQL from
    logging into a machine. There is also a possible additional attack
    vector with more malicious impact that has not been confirmed yet.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PAM-MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-auth/pam_mysql-0.7_rc1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://pam-mysql.sourceforge.net/News/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4713');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0056');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-18] PAM-MySQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PAM-MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-auth/pam_mysql", unaffected: make_list("ge 0.7_rc1"), vulnerable: make_list("lt 0.7_rc1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
