# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-05.xml
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
 script_id(23857);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-05");
 script_cve_id("CVE-2006-6120");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-05
(KOffice shared libraries: Heap corruption)


    Kees Cook of Ubuntu discovered that \'KLaola::readBigBlockDepot()\' in
    klaola.cc fills \'num_of_bbd_blocks\' while reading a .ppt (PowerPoint)
    file without proper sanitizing, resulting in an integer overflow
    subsequently overwriting the heap with parts of the file being read.
  
Impact

    By enticing a user to open a specially crafted PowerPoint file, an
    attacker could crash the application and possibly execute arbitrary
    code with the rights of the user running KOffice.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All koffice-libs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/koffice-libs-1.5.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6120');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-05] KOffice shared libraries: Heap corruption');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KOffice shared libraries: Heap corruption');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/koffice-libs", unaffected: make_list("ge 1.5.0"), vulnerable: make_list("lt 1.5.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
