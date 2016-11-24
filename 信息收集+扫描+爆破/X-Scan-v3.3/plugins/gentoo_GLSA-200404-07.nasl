# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-07.xml
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
 script_id(14472);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-07");
 script_cve_id("CVE-2004-1909");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-07
(ClamAV RAR Archive Remote Denial Of Service Vulnerability)


    Certain types of RAR archives, including those created by variants of
    the W32.Beagle.A@mm worm, may cause clamav to crash when it attempts to
    process them.
  
Impact

    This vulnerability causes a Denial of Service in the clamav process.
    Depending on	configuration, this may cause dependent services such as
    mail to fail as well.
  
Workaround

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    ClamAV users should upgrade to version 0.68.1 or later:
    # emerge sync
    # emerge -pv ">=app-antivirus/clamav-0.68.1"
    # emerge ">=app-antivirus/clamav-0.68.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.clamav.net/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1909');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-07] ClamAV RAR Archive Remote Denial Of Service Vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV RAR Archive Remote Denial Of Service Vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.68.1"), vulnerable: make_list("le 0.68")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
