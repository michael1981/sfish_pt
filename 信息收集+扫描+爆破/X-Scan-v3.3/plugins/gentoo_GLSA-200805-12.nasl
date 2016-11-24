# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-12.xml
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
 script_id(32303);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-12");
 script_cve_id("CVE-2008-1102", "CVE-2008-1103");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-12
(Blender: Multiple vulnerabilities)


    Stefan Cornelius (Secunia Research) reported a boundary error within
    the imb_loadhdr() function in in the file
    source/blender/imbuf/intern/radiance_hdr.c when processing RGBE images
    (CVE-2008-1102). Multiple vulnerabilities involving insecure usage of
    temporary files have also been reported (CVE-2008-1103).
  
Impact

    A remote attacker could entice a user to open a specially crafted file
    (.hdr or .blend), possibly resulting in the remote execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Blender users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/blender-2.43-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1102');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1103');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-12] Blender: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Blender: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/blender", unaffected: make_list("ge 2.43-r2"), vulnerable: make_list("lt 2.43-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
