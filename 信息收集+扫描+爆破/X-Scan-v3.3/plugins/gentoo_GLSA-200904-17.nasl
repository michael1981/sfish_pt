# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-17.xml
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
 script_id(36196);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200904-17");
 script_cve_id("CVE-2009-0193", "CVE-2009-0658", "CVE-2009-0927", "CVE-2009-0928", "CVE-2009-1061", "CVE-2009-1062");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-17
(Adobe Reader: User-assisted execution of arbitrary code)


    Multiple vulnerabilities have been discovered in Adobe Reader:
    Alin Rad Pop of Secunia Research reported a heap-based buffer overflow
    when processing PDF files containing a malformed JBIG2 symbol
    dictionary segment (CVE-2009-0193).
    A buffer overflow related to a non-JavaScript function call and
    possibly an embedded JBIG2 image stream has been reported
    (CVE-2009-0658).
    Tenable Network Security reported a stack-based buffer overflow that
    can be triggered via a crafted argument to the getIcon() method of a
    Collab object (CVE-2009-0927).
    Sean Larsson of iDefense Labs reported a heap-based buffer overflow
    when processing a PDF file containing a JBIG2 stream with a size
    inconsistency related to an unspecified table (CVE-2009-0928).
    Jonathan Brossard of the iViZ Security Research Team reported an
    unspecified vulnerability related to JBIG2 and input validation
    (CVE-2009-1061).
    Will Dormann of CERT/CC reported a vulnerability lading to memory
    corruption related to JBIG2 (CVE-2009-1062).
  
Impact

    A remote attacker could entice a user to open a specially crafted PDF
    document, possibly leading to the execution of arbitrary code with the
    privileges of the user running the application, or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-8.1.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0193');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0658');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0927');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0928');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1061');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1062');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-17] Adobe Reader: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Reader: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 8.1.4"), vulnerable: make_list("lt 8.1.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
