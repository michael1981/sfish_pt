# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-04.xml
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
 script_id(32152);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-04");
 script_cve_id("CVE-2008-1502", "CVE-2008-2041");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-04
(eGroupWare: Multiple vulnerabilities)


    A vulnerability has been reported in FCKEditor due to the way that file
    uploads are handled in the file
    editor/filemanager/upload/php/upload.php when a filename has multiple
    file extensions (CVE-2008-2041). Another vulnerability exists in the
    _bad_protocol_once() function in the file
    phpgwapi/inc/class.kses.inc.php, which allows remote attackers to
    bypass HTML filtering (CVE-2008-1502).
  
Impact

    The first vulnerability can be exploited to upload malicious files and
    execute arbitrary PHP code provided that a directory is writable by the
    webserver. The second vulnerability can be exploited by remote
    attackers via a specially crafted URL in order to conduct cross-site
    scripting attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All eGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/egroupware-1.4.004"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1502');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2041');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-04] eGroupWare: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'eGroupWare: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.4.004"), vulnerable: make_list("lt 1.4.004")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
