# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-23.xml
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
 script_id(23745);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-23");
 script_cve_id("CVE-2006-5072");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-23
(Mono: Insecure temporary file creation)


    Sebastian Krahmer of the SuSE Security Team discovered that the
    System.CodeDom.Compiler classes of Mono create temporary files with
    insecure permissions.
  
Impact

    A local attacker could create links in the temporary file directory,
    pointing to a valid file somewhere on the filesystem. When an affected
    class is called, this could result in the file being overwritten with
    the rights of the user running the script.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mono users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/mono-1.1.13.8.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5072');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-23] Mono: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mono: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/mono", unaffected: make_list("ge 1.1.13.8.1"), vulnerable: make_list("lt 1.1.13.8.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
