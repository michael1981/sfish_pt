# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-23.xml
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
 script_id(27555);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-23");
 script_cve_id("CVE-2007-4134");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-23
(Star: Directory traversal vulnerability)


    Robert Buchholz of the Gentoo Security team discovered a directory
    traversal vulnerability in the has_dotdot() function which does not
    identify //.. (slash slash dot dot) sequences in file names inside tar
    files.
  
Impact

    By enticing a user to extract a specially crafted tar archive, a remote
    attacker could extract files to arbitrary locations outside of the
    specified directory with the permissions of the user running Star.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Star users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/star-1.5_alpha84"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4134');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-23] Star: Directory traversal vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Star: Directory traversal vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/star", unaffected: make_list("ge 1.5_alpha84"), vulnerable: make_list("lt 1.5_alpha84")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
