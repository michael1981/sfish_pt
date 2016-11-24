# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-07.xml
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
 script_id(36095);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-07");
 script_cve_id("CVE-2009-1144");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-07
(Xpdf: Untrusted search path)


    Erik Wallin reported that Gentoo\'s Xpdf attempts to read the "xpdfrc"
    file from the current working directory if it cannot find a ".xpdfrc"
    file in the user\'s home directory. This is caused by a missing
    definition of the SYSTEM_XPDFRC macro when compiling a repackaged
    version of Xpdf.
  
Impact

    A local attacker could entice a user to run "xpdf" from a directory
    containing a specially crafted "xpdfrc" file, resulting in the
    execution of arbitrary code when attempting to, e.g., print a file.
  
Workaround

    Do not run Xpdf from untrusted working directories.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.02-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1144');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-07] Xpdf: Untrusted search path');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf: Untrusted search path');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.02-r2"), vulnerable: make_list("lt 3.02-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
