# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-01.xml
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
 script_id(20411);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200601-01");
 script_cve_id("CVE-2006-0071");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-01
(pinentry: Local privilege escalation)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has
    discovered that the pinentry ebuild incorrectly sets the permissions of
    the pinentry binaries upon installation, so that the sgid bit is set
    making them execute with the privileges of group ID 0.
  
Impact

    A user of pinentry could potentially read and overwrite files with
    a group ID of 0.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All pinentry users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/pinentry-0.7.2-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0071');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-01] pinentry: Local privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pinentry: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/pinentry", unaffected: make_list("ge 0.7.2-r2"), vulnerable: make_list("lt 0.7.2-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
