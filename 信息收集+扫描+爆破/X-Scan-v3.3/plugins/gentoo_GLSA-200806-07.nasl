# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200806-07.xml
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
 script_id(33243);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200806-07");
 script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200806-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200806-07
(X.Org X server: Multiple vulnerabilities)


    Regenrecht reported multiple vulnerabilities in various X server
    extensions via iDefense:
    The
    SProcSecurityGenerateAuthorization() and SProcRecordCreateContext()
    functions of the RECORD and Security extensions are lacking proper
    parameter validation (CVE-2008-1377).
    An integer overflow is
    possible in the function ShmPutImage() of the MIT-SHM extension
    (CVE-2008-1379).
    The RENDER extension contains several
    possible integer overflows in the AllocateGlyph() function
    (CVE-2008-2360) which could possibly lead to a heap-based buffer
    overflow. Further possible integer overflows have been found in the
    ProcRenderCreateCursor() function (CVE-2008-2361) as well as in the
    SProcRenderCreateLinearGradient(), SProcRenderCreateRadialGradient()
    and SProcRenderCreateConicalGradient() functions (CVE-2008-2362).
  
Impact

    Exploitation of these vulnerabilities could possibly lead to the remote
    execution of arbitrary code with root privileges, if the server is
    running as root, which is the default. It is also possible to crash the
    server by making use of these vulnerabilities.
  
Workaround

    It is possible to avoid these vulnerabilities by disabling the affected
    server extensions. Therefore edit the configuration file
    (/etc/X11/xorg.conf) to contain the following in the appropriate
    places:
      Section "Extensions"
    	Option "MIT-SHM" "disable"
    	Option "RENDER" "disable"
    	Option "SECURITY" "disable"
      EndSection
      Section "Module"
       Disable "record"
      EndSection
  
');
script_set_attribute(attribute:'solution', value: '
    All X.org X Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-server-1.3.0.0-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1377');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1379');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2360');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2361');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2362');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200806-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200806-07] X.Org X server: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org X server: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-server", unaffected: make_list("ge 1.3.0.0-r6"), vulnerable: make_list("lt 1.3.0.0-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
