# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-18.xml
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
 script_id(20371);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200512-18");
 script_cve_id("CVE-2005-4595");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-18
(XnView: Privilege escalation)


    Krzysiek Pawlik of Gentoo Linux discovered that the XnView package for
    IA32 used the DT_RPATH field insecurely, causing the dynamic loader to
    search for shared libraries in potentially untrusted directories.
  
Impact

    A local attacker could create a malicious shared object that would be
    loaded and executed when a user attempted to use an XnView utility.
    This would allow a malicious user to effectively hijack XnView and
    execute arbitrary code with the privileges of the user running the
    program.
  
Workaround

    The system administrator may use the chrpath utility to remove the
    DT_RPATH field from the XnView utilities:
    # emerge app-admin/chrpath
    # chrpath --delete /opt/bin/nconvert /opt/bin/nview /opt/bin/xnview
  
');
script_set_attribute(attribute:'solution', value: '
    All XnView users on the x86 platform should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-misc/xnview-1.70-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4595');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-18] XnView: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XnView: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-misc/xnview", arch: "x86", unaffected: make_list("ge 1.70-r1"), vulnerable: make_list("lt 1.70-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
