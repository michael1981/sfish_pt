# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-13.xml
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
 script_id(15647);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200411-13");
 script_cve_id("CVE-2004-1107", "CVE-2004-1108");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-13
(Portage, Gentoolkit: Temporary file vulnerabilities)


    dispatch-conf and qpkg use predictable filenames for temporary files.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    an affected script is called, this would result in the file to be
    overwritten with the rights of the user running the dispatch-conf or
    qpkg, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Portage users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/portage-2.0.51-r3"
    All Gentoolkit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-portage/gentoolkit-0.2.0_pre8-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1107');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1108');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-13] Portage, Gentoolkit: Temporary file vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Portage, Gentoolkit: Temporary file vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/portage", unaffected: make_list("ge 2.0.51-r3"), vulnerable: make_list("le 2.0.51-r2")
)) { security_note(0); exit(0); }
if (qpkg_check(package: "app-portage/gentoolkit", unaffected: make_list("ge 0.2.0_pre10-r1", "rge 0.2.0_pre8-r1"), vulnerable: make_list("le 0.2.0_pre10")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
