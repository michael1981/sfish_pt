# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-29.xml
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
 script_id(15777);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200411-29");
 script_cve_id("CVE-2004-0947", "CVE-2004-1027");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-29
(unarj: Long filenames buffer overflow and a path traversal vulnerability)


    unarj has a bounds checking vulnerability within the handling of
    long filenames in archives. It also fails to properly sanitize paths
    when extracting an archive (if the "x" option is used to preserve
    paths).
  
Impact

    An attacker could trigger a buffer overflow or a path traversal by
    enticing a user to open an archive containing specially-crafted path
    names, potentially resulting in the overwrite of files or execution of
    arbitrary code with the permissions of the user running unarj.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All unarj users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/unarj-2.63a-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0947');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1027');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-29] unarj: Long filenames buffer overflow and a path traversal vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'unarj: Long filenames buffer overflow and a path traversal vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/unarj", unaffected: make_list("ge 2.63a-r2"), vulnerable: make_list("lt 2.63a-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
