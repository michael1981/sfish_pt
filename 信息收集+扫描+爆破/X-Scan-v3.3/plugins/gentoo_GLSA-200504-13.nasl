# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-13.xml
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
 script_id(18060);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200504-13");
 script_cve_id("CVE-2005-0941");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-13
(OpenOffice.Org: DOC document Heap Overflow)


    AD-LAB has discovered a heap overflow in the "StgCompObjStream::Load()"
    function when processing DOC documents.
  
Impact

    An attacker could design a malicious DOC document containing a
    specially crafted header which, when processed by OpenOffice.Org, would
    result in the execution of arbitrary code with the rights of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-1.1.4-r1"
    All OpenOffice.Org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-1.1.4-r1"
    All OpenOffice.Org Ximian users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/openoffice-ximian
    Note to PPC users: There is no stable OpenOffice.Org fixed version for
    the PPC architecture. Affected users should switch to the latest
    OpenOffice.Org Ximian version.
    Note to SPARC users: There is no stable OpenOffice.Org fixed version
    for the SPARC architecture. Affected users should switch to the latest
    OpenOffice.Org Ximian version.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.openoffice.org/issues/show_bug.cgi?id=46388');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0941');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-13] OpenOffice.Org: DOC document Heap Overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.Org: DOC document Heap Overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice-ximian", unaffected: make_list("ge 1.3.9-r1", "rge 1.3.6-r1", "rge 1.3.7-r1"), vulnerable: make_list("lt 1.3.9-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
