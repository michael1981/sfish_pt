# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-35.xml
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
 script_id(15406);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-35");
 script_cve_id("CVE-2004-0749");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-35 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-35
(Subversion: Metadata information leak)


    There is a bug in mod_authz_svn that causes it to reveal logged metadata
    regarding commits to protected areas.
  
Impact

    Protected files themselves will not be revealed, but an attacker could use
    the metadata to reveal the existence of protected areas, such as paths,
    file versions, and the commit logs from those areas.
  
Workaround

    Rather than using mod_authz_svn, move protected areas into seperate
    repositories and use native Apache authentication to make these
    repositories unreadable.
  
');
script_set_attribute(attribute:'solution', value: '
    All Subversion users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-util/subversion-1.0.8"
    # emerge ">=dev-util/subversion-1.0.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0749');
script_set_attribute(attribute: 'see_also', value: 'http://subversion.tigris.org/security/CAN-2004-0749-advisory.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-35.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-35] Subversion: Metadata information leak');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Subversion: Metadata information leak');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
