# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-23.xml
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
 script_id(35904);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200903-23");
 script_cve_id("CVE-2008-3873", "CVE-2008-4401", "CVE-2008-4503", "CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824", "CVE-2008-5361", "CVE-2008-5362", "CVE-2008-5363", "CVE-2008-5499", "CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0521");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-23
(Adobe Flash Player: Multiple vulnerabilities)

Impact

    A remote attacker could entice a user to open a specially crafted SWF
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user or a Denial of Service (crash). Furthermore a
    remote attacker could gain access to sensitive information, disclose
    memory contents by enticing a user to open a specially crafted PDF file
    inside a Flash application, modify the victim\'s clipboard or render it
    temporarily unusable, persuade a user into uploading or downloading
    files, bypass security restrictions with the assistance of the user to
    gain access to camera and microphone, conduct Cross-Site Scripting and
    HTTP Header Splitting attacks, bypass the "non-root domain policy" of
    Flash, and gain escalated privileges.
  
Workaround

    There is no known workaround at this time.
  

');
script_set_attribute(attribute:'solution', value: '
    All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-plugins/adobe-flash-10.0.22.87"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3873');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4401');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4503');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4818');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4819');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4821');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4822');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4823');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4824');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5361');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5362');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5363');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5499');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0114');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0519');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0520');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0521');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-23] Adobe Flash Player: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Flash Player: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-plugins/adobe-flash", unaffected: make_list("ge 10.0.22.87"), vulnerable: make_list("lt 10.0.22.87")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
