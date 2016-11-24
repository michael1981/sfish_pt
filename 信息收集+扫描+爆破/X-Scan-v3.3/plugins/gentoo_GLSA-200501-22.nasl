# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-22.xml
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
 script_id(16413);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-22");
 script_cve_id("CVE-2005-0002");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-22
(poppassd_pam: Unauthorized password changing)


    Gentoo Linux developer Marcus Hanwell discovered that poppassd_pam
    did not check that the old password was valid before changing
    passwords. Our investigation revealed that poppassd_pam did not call
    pam_authenticate before calling pam_chauthtok.
  
Impact

    A remote attacker could change the system password of any user,
    including root. This leads to a complete compromise of the POP
    accounts, and may also lead to a complete root compromise of the
    affected server, if it also provides shell access authenticated using
    system passwords.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All poppassd_pam users should migrate to the new package called
    poppassd_ceti:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/poppassd_ceti-1.8.4"
    Note: Portage will automatically replace the poppassd_pam
    package by the poppassd_ceti package.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0002');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-22] poppassd_pam: Unauthorized password changing');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'poppassd_pam: Unauthorized password changing');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/poppassd_ceti", unaffected: make_list("ge 1.8.4"), vulnerable: make_list("le 1.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-mail/poppassd_pam", unaffected: make_list(), vulnerable: make_list("le 1.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
