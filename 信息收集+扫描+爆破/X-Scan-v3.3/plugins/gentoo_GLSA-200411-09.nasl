# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-09.xml
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
 script_id(15634);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200411-09");
 script_cve_id("CVE-2004-1001");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-09
(shadow: Unauthorized modification of account information)


    Martin Schulze reported a flaw in the passwd_check() function in
    "libmisc/pwdcheck.c" which is used by chfn and chsh.
  
Impact

    A logged-in local user with an expired password may be able to use chfn and
    chsh to change his standard shell or GECOS information (full name, phone
    number...) without being required to change his password.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All shadow users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/shadow-4.0.5-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://ftp.pld.org.pl/software/shadow/NEWS');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1001');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-09] shadow: Unauthorized modification of account information');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'shadow: Unauthorized modification of account information');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/shadow", unaffected: make_list("ge 4.0.5-r1"), vulnerable: make_list("lt 4.0.5-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
