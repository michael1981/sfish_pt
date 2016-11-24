# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-05.xml
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
 script_id(14491);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200405-05");
 script_cve_id("CVE-2004-0233");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-05
(Utempter symlink vulnerability)


    Utempter contains a vulnerability that may allow local users to overwrite
    arbitrary files via a symlink attack.
  
Impact

    This vulnerability may allow arbitrary files to be overwritten with root
    privileges.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of utempter.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of utempter should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=sys-apps/utempter-0.5.5.4"
    # emerge ">=sys-apps/utempter-0.5.5.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0233');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-05] Utempter symlink vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Utempter symlink vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/utempter", unaffected: make_list("ge 0.5.5.4"), vulnerable: make_list("lt 0.5.5.4")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
