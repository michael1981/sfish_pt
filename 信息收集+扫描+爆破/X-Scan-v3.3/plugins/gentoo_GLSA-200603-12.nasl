# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-12.xml
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
 script_id(21085);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-12");
 script_cve_id("CVE-2006-1269");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-12
(zoo: Buffer overflow)


    zoo is vulnerable to a new buffer overflow due to insecure use of
    the strcpy() function when trying to create an archive from certain
    directories or filenames.
  
Impact

    An attacker could exploit this issue by enticing a user to create
    a zoo archive of specially crafted directories and filenames, possibly
    leading to the execution of arbitrary code with the rights of the user
    running zoo.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All zoo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/zoo-2.10-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=183426');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1269');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-12] zoo: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zoo: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/zoo", unaffected: make_list("ge 2.10-r2"), vulnerable: make_list("lt 2.10-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
