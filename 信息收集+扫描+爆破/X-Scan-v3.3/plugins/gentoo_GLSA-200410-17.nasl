# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-17.xml
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
 script_id(15526);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-17");
 script_cve_id("CVE-2004-0752");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-17
(OpenOffice.org: Temporary files disclosure)


    On start-up, OpenOffice.org 1.1.2 creates a temporary directory with
    insecure permissions. When a document is saved, a compressed copy of it can
    be found in that directory.
  
Impact

    A malicious local user could obtain the temporary files and thus read
    documents belonging to other users.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All affected OpenOffice.org users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-1.1.3"
    # emerge ">=app-office/openoffice-1.1.3"
    All affected OpenOffice.org binary users should upgrade to the latest
    version:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-bin-1.1.3"
    # emerge ">=app-office/openoffice-bin-1.1.3"
    All affected OpenOffice.org Ximian users should upgrade to the latest
    version:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-ximian-1.3.4"
    # emerge ">=app-office/openoffice-1.3.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0752');
script_set_attribute(attribute: 'see_also', value: 'http://www.openoffice.org/issues/show_bug.cgi?id=33357');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-17] OpenOffice.org: Temporary files disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: Temporary files disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("lt 1.1.2", "ge 1.1.3"), vulnerable: make_list("eq 1.1.2")
)) { security_note(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice-ximian", unaffected: make_list("lt 1.1.60", "ge 1.3.4"), vulnerable: make_list("eq 1.1.60", "eq 1.1.61")
)) { security_note(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("lt 1.1.2", "ge 1.1.3"), vulnerable: make_list("eq 1.1.2")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
