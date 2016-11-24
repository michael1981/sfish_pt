# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-05.xml
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
 script_id(26945);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-05
(QGit: Insecure temporary file creation)


    Raphael Marichez discovered that the DataLoader::doStart() method
    creates temporary files in an insecure manner and executes them.
  
Impact

    A local attacker could perform a symlink attack, possibly overwriting
    files or executing arbitrary code with the rights of the user running
    QGit.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All QGit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/qgit-1.5.7"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://nvd.nist.gov/nvd.cfm?cvename=CVE-2007-4631');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-05] QGit: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'QGit: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/qgit", unaffected: make_list("ge 1.5.7"), vulnerable: make_list("lt 1.5.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
