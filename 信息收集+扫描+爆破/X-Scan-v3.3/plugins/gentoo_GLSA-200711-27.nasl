# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-27.xml
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
 script_id(28266);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-27");
 script_cve_id("CVE-2007-5395");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-27
(Link Grammar: User-assisted execution of arbitrary code)


    Alin Rad Pop from Secunia Research discovered a boundary error in the
    function separate_sentence() in file tokenize.c when processing an
    overly long word which might lead to a stack-based buffer overflow.
  
Impact

    A remote attacker could entice a user to parse a specially crafted
    sentence, resulting in the remote execution of arbitrary code with the
    privileges of the user running the application. Note that this
    vulnerability may be triggered by an application using Link Grammar to
    parse sentences (e.g. AbiWord).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Link Grammar users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/link-grammar-4.2.4-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5395');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-27] Link Grammar: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Link Grammar: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/link-grammar", unaffected: make_list("ge 4.2.4-r1"), vulnerable: make_list("lt 4.2.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
