# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-01.xml
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
 script_id(40879);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-01");
 script_cve_id("CVE-2009-0887");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-01
(Linux-PAM: Privilege escalation)


    Marcus Granado repoted that Linux-PAM does not properly handle user
    names that contain Unicode characters. This is related to integer
    signedness errors in the pam_StrTok() function in libpam/pam_misc.c.
  
Impact

    A remote attacker could exploit this vulnerability to cause a Denial of
    Service. A remote authenticated attacker could exploit this
    vulnerability to log in to a system with the account of a user that has
    a similar user name, but with non-ASCII characters.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Linux-PAM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =sys-libs/pam-1.0.4
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0887');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-01] Linux-PAM: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux-PAM: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-libs/pam", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
