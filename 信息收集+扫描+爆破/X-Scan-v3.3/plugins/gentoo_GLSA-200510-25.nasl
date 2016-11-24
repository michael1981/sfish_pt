# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-25.xml
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
 script_id(20118);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200510-25");
 script_cve_id("CVE-2005-3184", "CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3245", "CVE-2005-3246", "CVE-2005-3247", "CVE-2005-3248", "CVE-2005-3249", "CVE-2005-3313");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-25
(Ethereal: Multiple vulnerabilities in protocol dissectors)


    There are numerous vulnerabilities in versions of Ethereal prior
    to 0.10.13, including:
    The SLIM3 and AgentX dissectors
    could overflow a buffer (CVE-2005-3243).
    iDEFENSE discovered a
    buffer overflow in the SRVLOC dissector (CVE-2005-3184).
    Multiple potential crashes in many dissectors have been fixed, see
    References for further details.
    Furthermore an infinite
    loop was discovered in the IRC protocol dissector of the 0.10.13
    release (CVE-2005-3313).
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal or execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.13-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3184');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3241');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3242');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3243');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3244');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3245');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3246');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3247');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3248');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3249');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3313');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/appnotes/enpa-sa-00021.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-25] Ethereal: Multiple vulnerabilities in protocol dissectors');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities in protocol dissectors');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.13-r1"), vulnerable: make_list("lt 0.10.13-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
