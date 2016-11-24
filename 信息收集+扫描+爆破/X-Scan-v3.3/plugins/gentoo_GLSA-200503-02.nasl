# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-02.xml
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
 script_id(17249);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200503-02");
 script_cve_id("CVE-2005-0258", "CVE-2005-0259");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-02
(phpBB: Multiple vulnerabilities)


    It was discovered that phpBB contains a flaw in the session
    handling code and a path disclosure bug. AnthraX101 discovered that
    phpBB allows local users to read arbitrary files, if the "Enable remote
    avatars" and "Enable avatar uploading" options are set (CAN-2005-0259).
    He also found out that incorrect input validation in
    "usercp_avatar.php" and "usercp_register.php" makes phpBB vulnerable to
    directory traversal attacks, if the "Gallery avatars" setting is
    enabled (CAN-2005-0258).
  
Impact

    Remote attackers can exploit the session handling flaw to gain
    phpBB administrator rights. By providing a local and a remote location
    for an avatar and setting the "Upload Avatar from a URL:" field to
    point to the target file, a malicious local user can read arbitrary
    local files. By inserting "/../" sequences into the "avatarselect"
    parameter, a remote attacker can exploit the directory traversal
    vulnerability to delete arbitrary files. A flaw in the "viewtopic.php"
    script can be exploited to expose the full path of PHP scripts.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpBB users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpBB-2.0.13"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0258');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0259');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=267563');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-02] phpBB: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpBB", unaffected: make_list("ge 2.0.13"), vulnerable: make_list("lt 2.0.13")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
